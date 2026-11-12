package butterflymx

import (
	"context"
	"fmt"
	"iter"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/stevenmirabito/butterflymx-go/internal/jsonapi"
)

// KeychainKind is the kind of a keychain. Unknown values returned by the
// server are preserved as-is.
type KeychainKind string

// Keychain kinds.
const (
	// KindCustom is a pass valid for one continuous window.
	KindCustom KeychainKind = "custom"
	// KindRecurring is a pass valid on selected weekdays between two dates.
	KindRecurring KeychainKind = "recurring"
	// KindDeliveryPass is a one-time pass for couriers, without a recipient.
	KindDeliveryPass KeychainKind = "delivery_pass"
)

// KeychainStatus selects which passes [Client.Keychains] lists.
type KeychainStatus string

// Keychain statuses for [KeychainFilter.Status]. The server ignores any other
// value and returns every pass, so these are the only two filters.
const (
	// StatusActive lists passes that have not ended yet, including passes
	// whose start is still in the future.
	StatusActive KeychainStatus = "active"
	// StatusExpired lists passes whose end has passed, and delivery passes
	// whose one-time key has been used.
	StatusExpired KeychainStatus = "expired"
)

// Keychain is a time-bounded grant of access (a "pass"): one or more virtual
// keys that open a set of doors during a schedule.
//
// The server derives every schedule representation, whichever way the pass was
// created (spec §7.2): StartsAt and EndsAt are absolute instants, while
// StartDate, EndDate, TimeFrom and TimeTo are in the building's local time zone.
// TimeFrom and TimeTo are only meaningful as a daily window for
// [KindRecurring] passes. Weekdays is empty unless the pass is recurring.
type Keychain struct {
	ID   ID
	Name string
	Kind KeychainKind

	StartsAt, EndsAt   time.Time
	StartDate, EndDate Date
	TimeFrom, TimeTo   TimeOfDay
	Weekdays           []Weekday
	// AllowUnitAccess is always false in the official app. Its meaning is
	// unverified.
	AllowUnitAccess bool

	// VirtualKeys are the credentials of the pass. Which of their fields are
	// populated depends on what the request included: a key that the response
	// did not include has only its ID set.
	VirtualKeys []VirtualKey
	// Devices are the panels and cloud controllers behind the pass's doors.
	Devices []KeychainDevice
}

// Schedule returns the pass's schedule: a [CustomSchedule] for custom and
// delivery-pass keychains, a [RecurringSchedule] for recurring ones, and nil
// for kinds this library does not know. Recurring dates and times are in the
// building's local time zone.
func (k Keychain) Schedule() Schedule {
	switch k.Kind {
	case KindCustom, KindDeliveryPass:
		return CustomSchedule{StartsAt: k.StartsAt, EndsAt: k.EndsAt}
	case KindRecurring:
		return RecurringSchedule{
			Weekdays:  slices.Clone(k.Weekdays),
			From:      k.TimeFrom,
			To:        k.TimeTo,
			StartDate: k.StartDate,
			EndDate:   k.EndDate,
		}
	}
	return nil
}

// KeychainDevice is the hardware behind a pass's doors: an intercom panel or a
// cloud access controller.
type KeychainDevice struct {
	ID ID
	// Type is the REST resource type: "panels" or "cloud_keyz_controllers".
	// The two have independent ID spaces. Other values are preserved.
	Type       string
	Name       string
	BuildingID ID
}

// KeychainFilter selects and pages the passes returned by [Client.Keychains]
// and [Client.KeychainsSeq].
type KeychainFilter struct {
	// Status defaults to [StatusActive].
	Status KeychainStatus
	// Kinds filters client-side (the server returns delivery passes along with
	// guest passes). Empty means all kinds.
	Kinds []KeychainKind
	// PageSize is the page size requested from the server; default 20.
	PageSize int
}

const (
	restDefaultPageSize = 20
	restKeychainInclude = "virtual_keys,devices,virtual_keys.door_releases,virtual_keys.door_releases.panel"
	restListInclude     = "devices,virtual_keys,virtual_keys.door_releases,virtual_keys.door_releases.panel"
)

// restFail wraps a client-side error in an *Error carrying the operation.
func restFail(op string, err error) error { return &Error{Op: op, Err: err} }

// ---- decoding ---------------------------------------------------------------

type restKeychainAttrs struct {
	Name            string   `json:"name"`
	Kind            string   `json:"kind"`
	StartsAt        string   `json:"starts_at"`
	EndsAt          string   `json:"ends_at"`
	StartDate       string   `json:"start_date"`
	EndDate         string   `json:"end_date"`
	TimeFrom        string   `json:"time_from"`
	TimeTo          string   `json:"time_to"`
	Weekdays        []string `json:"weekdays"`
	AllowUnitAccess bool     `json:"allow_unit_access"`
}

type restDeviceAttrs struct {
	Name string `json:"name"`
}

// restID parses a resource ID, yielding 0 for a malformed one (lenient decode).
func restID(s string) ID {
	id, err := ParseID(s)
	if err != nil {
		return 0
	}
	return id
}

// restTime parses an instant, yielding the zero time for empty or malformed
// values (lenient decode).
func restTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := parseInstant(s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func restOptTime(s string) *time.Time {
	t := restTime(s)
	if t.IsZero() {
		return nil
	}
	return &t
}

// restDevice builds a KeychainDevice from an identifier and, if the document
// included it, its resource.
func restDevice(id jsonapi.Identifier, idx *jsonapi.Index) (KeychainDevice, error) {
	d := KeychainDevice{ID: restID(id.ID), Type: id.Type}
	res, ok := idx.Get(id)
	if !ok {
		return d, nil
	}
	var a restDeviceAttrs
	if err := res.DecodeAttributes(&a); err != nil {
		return d, fmt.Errorf("decode %s %s: %w", id.Type, id.ID, err)
	}
	d.Name = a.Name
	if b, err := res.Relationships["building"].One(); err == nil && b != nil {
		d.BuildingID = restID(b.ID)
	}
	return d, nil
}

// restBuildKeychain converts a keychains resource, resolving its relationships
// through idx.
func restBuildKeychain(r jsonapi.Resource, idx *jsonapi.Index) (Keychain, error) {
	var a restKeychainAttrs
	if err := r.DecodeAttributes(&a); err != nil {
		return Keychain{}, fmt.Errorf("decode keychain %s: %w", r.ID, err)
	}
	k := Keychain{
		ID:              restID(r.ID),
		Name:            a.Name,
		Kind:            KeychainKind(a.Kind),
		StartsAt:        restTime(a.StartsAt),
		EndsAt:          restTime(a.EndsAt),
		AllowUnitAccess: a.AllowUnitAccess,
	}
	k.StartDate, _ = ParseDate(a.StartDate)
	k.EndDate, _ = ParseDate(a.EndDate)
	k.TimeFrom, _ = ParseTimeOfDay(a.TimeFrom)
	k.TimeTo, _ = ParseTimeOfDay(a.TimeTo)
	for _, w := range a.Weekdays {
		if p, err := ParseWeekday(w); err == nil {
			k.Weekdays = append(k.Weekdays, p)
		} else {
			k.Weekdays = append(k.Weekdays, Weekday(w)) // preserve unknown values
		}
	}

	vkIDs, err := r.Relationships["virtual_keys"].Many()
	if err != nil {
		return Keychain{}, fmt.Errorf("keychain %s: virtual_keys: %w", r.ID, err)
	}
	for _, id := range vkIDs {
		res, ok := idx.Get(id)
		if !ok {
			k.VirtualKeys = append(k.VirtualKeys, VirtualKey{ID: restID(id.ID)})
			continue
		}
		vk, err := restBuildVirtualKey(res, idx)
		if err != nil {
			return Keychain{}, err
		}
		k.VirtualKeys = append(k.VirtualKeys, vk)
	}
	devIDs, err := r.Relationships["devices"].Many()
	if err != nil {
		return Keychain{}, fmt.Errorf("keychain %s: devices: %w", r.ID, err)
	}
	for _, id := range devIDs {
		d, err := restDevice(id, idx)
		if err != nil {
			return Keychain{}, err
		}
		k.Devices = append(k.Devices, d)
	}
	return k, nil
}

// restKeychainDoc decodes a single-keychain document.
func restKeychainDoc(op string, doc *jsonapi.Document) (*Keychain, error) {
	if doc == nil {
		return nil, restFail(op, fmt.Errorf("empty response"))
	}
	res, err := doc.One()
	if err != nil {
		return nil, restFail(op, err)
	}
	k, err := restBuildKeychain(res, doc.Index())
	if err != nil {
		return nil, restFail(op, err)
	}
	return &k, nil
}

// ---- reads ------------------------------------------------------------------

// Keychains lists a tenant's passes, collecting every page. See
// [Client.KeychainsSeq] to page lazily. The result is in server order (newest
// end first); delivery passes are included unless filtered out with
// f.Kinds. tenantID must be a tenant global ID (otherwise the error wraps
// [ErrIDType]).
func (c *Client) Keychains(ctx context.Context, tenantID GlobalID, f KeychainFilter) ([]Keychain, error) {
	var out []Keychain
	for k, err := range c.KeychainsSeq(ctx, tenantID, f) {
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

// KeychainsSeq is the lazy form of [Client.Keychains]: pages are fetched as the
// iteration proceeds. An error ends the sequence and is yielded as the last
// element together with a zero Keychain.
func (c *Client) KeychainsSeq(ctx context.Context, tenantID GlobalID, f KeychainFilter) iter.Seq2[Keychain, error] {
	const op = "Keychains"
	return func(yield func(Keychain, error) bool) {
		tid, err := tenantID.As(TypeTenant)
		if err != nil {
			yield(Keychain{}, restFail(op, err))
			return
		}
		status := f.Status
		if status == "" {
			status = StatusActive
		}
		size := f.PageSize
		if size <= 0 {
			size = restDefaultPageSize
		}
		for page := 1; ; page++ {
			q := url.Values{
				"filter[tenant]": {tid.String()},
				"filter[status]": {string(status)},
				"include":        {restListInclude},
				"page[size]":     {strconv.Itoa(size)},
				"page[number]":   {strconv.Itoa(page)},
			}
			doc, err := c.jsonAPI(ctx, op, http.MethodGet, "/v3/access_codes", q, nil)
			if err != nil {
				yield(Keychain{}, err)
				return
			}
			if doc == nil {
				return
			}
			res, err := doc.Many()
			if err != nil {
				yield(Keychain{}, restFail(op, err))
				return
			}
			idx := doc.Index()
			for _, r := range res {
				k, err := restBuildKeychain(r, idx)
				if err != nil {
					yield(Keychain{}, restFail(op, err))
					return
				}
				if len(f.Kinds) > 0 && !slices.Contains(f.Kinds, k.Kind) {
					continue
				}
				if !yield(k, nil) {
					return
				}
			}
			if !jsonapi.HasNext(doc.Links) || len(res) == 0 {
				return
			}
		}
	}
}

func (c *Client) restGetKeychain(ctx context.Context, op string, id ID) (*Keychain, error) {
	if id <= 0 {
		return nil, restFail(op, restInvalid("keychain id is required"))
	}
	doc, err := c.jsonAPI(ctx, op, http.MethodGet, "/v3/keychains/"+id.String(),
		url.Values{"include": {restKeychainInclude}}, nil)
	if err != nil {
		return nil, err
	}
	return restKeychainDoc(op, doc)
}

// Keychain fetches one pass with its virtual keys (including their door
// releases) and devices.
func (c *Client) Keychain(ctx context.Context, id ID) (*Keychain, error) {
	return c.restGetKeychain(ctx, "Keychain", id)
}

// ---- writes -----------------------------------------------------------------

// restKeychainWrite is the attribute set of a keychain request. Pointer
// members without omitzero encode as explicit nulls, as the app sends them.
type restKeychainWrite struct {
	Kind            *string         `json:"kind"`
	Name            string          `json:"name"`
	StartsAt        *string         `json:"starts_at"`
	EndsAt          *string         `json:"ends_at"`
	StartDate       *string         `json:"start_date"`
	EndDate         *string         `json:"end_date"`
	TimeFrom        *string         `json:"time_from"`
	TimeTo          *string         `json:"time_to"`
	Weekdays        *[]string       `json:"weekdays"`
	AllowUnitAccess *bool           `json:"allow_unit_access"`
	Recipients      []restRecipient `json:"recipients,omitzero"`
}

// restReadAttrs renders k as the full attribute set "as read", which is what
// the app sends when it updates a delivery pass.
func restReadAttrs(k *Keychain) restKeychainWrite {
	opt := func(s string) *string {
		if s == "" {
			return nil
		}
		return &s
	}
	a := restKeychainWrite{
		Kind:            opt(string(k.Kind)),
		Name:            k.Name,
		StartDate:       opt(k.StartDate.String()),
		EndDate:         opt(k.EndDate.String()),
		TimeFrom:        opt(k.TimeFrom.String()),
		TimeTo:          opt(k.TimeTo.String()),
		Weekdays:        restPtr(restWeekdays(k.Weekdays)),
		AllowUnitAccess: restPtr(k.AllowUnitAccess),
	}
	if !k.StartsAt.IsZero() {
		a.StartsAt = restPtr(formatInstant(k.StartsAt))
	}
	if !k.EndsAt.IsZero() {
		a.EndsAt = restPtr(formatInstant(k.EndsAt))
	}
	return a
}

// restAccessPoints converts access point global IDs to numeric REST IDs,
// failing fast with ErrIDType and dropping duplicates.
func restAccessPoints(gids []GlobalID) ([]string, error) {
	out := make([]string, 0, len(gids))
	for _, g := range gids {
		id, err := g.As(TypeAccessPoint)
		if err != nil {
			return nil, err
		}
		if s := id.String(); !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

func restTenantRel(g GlobalID) (jsonapi.RelationshipObject, error) {
	id, err := g.As(TypeTenant)
	if err != nil {
		return jsonapi.RelationshipObject{}, err
	}
	return jsonapi.ToOne("tenants", id.String()), nil
}

// CreateKeychainParams describes a new guest pass.
type CreateKeychainParams struct {
	// TenantID is the tenant (residency) the pass belongs to; a tenant global ID.
	TenantID GlobalID
	// AccessPointIDs are the doors, as access point global IDs. At least one
	// is required, and each door must support virtual keys.
	AccessPointIDs []GlobalID
	// Name labels the pass; required.
	Name string
	// Schedule is a [CustomSchedule] or a [RecurringSchedule]; required.
	Schedule Schedule
	// Recipients each get a virtual key, delivered by ButterflyMX by email or
	// SMS. The keys are created by the same request as the pass.
	Recipients []Recipient
	// AllowUnitAccess is sent as-is. The app always sends false; its meaning
	// is unverified.
	AllowUnitAccess bool
}

// CreateKeychain creates a guest pass and one virtual key per recipient
// (POST /v3/keychains/custom or /recurring, chosen by the schedule type). The
// returned keychain carries the keys with their PIN, QR code URL and
// instructions URL.
//
// Parameters are validated before any request is sent; errors wrap
// [ErrValidation] or [ErrIDType]. [Options.SkipClientValidation] turns the
// validation off for probing. The server's own validation errors map to
// [ErrValidation] too (HTTP 400, with `source.pointer` and `detail` per
// problem; passes may not exceed 365 days).
//
// CreateKeychain is not idempotent and is never retried automatically (other
// than the single re-authentication retry after a 401), because a repeated
// request could create a second pass and send a second email or SMS to the
// guest. After an ambiguous failure (a timeout, say), reconcile with
// [Client.Keychains] before trying again.
func (c *Client) CreateKeychain(ctx context.Context, p CreateKeychainParams) (*Keychain, error) {
	const op = "CreateKeychain"
	tenant, err := restTenantRel(p.TenantID)
	if err != nil {
		return nil, restFail(op, err)
	}
	aps, err := restAccessPoints(p.AccessPointIDs)
	if err != nil {
		return nil, restFail(op, err)
	}
	skip := c.cfg.SkipClientValidation
	name := p.Name
	if !skip {
		if len(aps) == 0 {
			return nil, restFail(op, restInvalid("at least one access point is required"))
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, restFail(op, restInvalid("name is required"))
		}
	}
	sched, err := restValidateSchedule(p.Schedule, skip)
	if err != nil {
		return nil, restFail(op, err)
	}
	recips, err := restRecipients(p.Recipients, skip)
	if err != nil {
		return nil, restFail(op, err)
	}
	a := restKeychainWrite{Name: name, AllowUnitAccess: restPtr(p.AllowUnitAccess), Recipients: recips}
	kind := restApplySchedule(&a, sched)
	doc, err := c.jsonAPI(ctx, op, http.MethodPost, "/v3/keychains/"+kind, nil, &jsonapi.ResourceObject{
		Type:       "keychains",
		Attributes: a,
		Relationships: map[string]jsonapi.RelationshipObject{
			"tenant":        tenant,
			"access_points": jsonapi.ToMany("access_points", aps...),
			"virtual_keys":  jsonapi.ToMany("virtual_keys"),
			"devices":       jsonapi.ToMany("devices"),
		},
	})
	if err != nil {
		return nil, err
	}
	return restKeychainDoc(op, doc)
}

// DeleteKeychain deletes a pass and revokes all of its virtual keys
// (DELETE /v3/keychains/{id}). Deleting a pass that is already gone yields an
// error satisfying errors.Is(err, [ErrNotFound]), except that a retried
// delete answered 404 counts as success.
func (c *Client) DeleteKeychain(ctx context.Context, id ID) error {
	const op = "DeleteKeychain"
	if id <= 0 {
		return restFail(op, restInvalid("keychain id is required"))
	}
	_, err := c.jsonAPI(ctx, op, http.MethodDelete, "/v3/keychains/"+id.String(), nil, nil)
	return err
}

func restKeyIDs(k *Keychain) []string {
	ids := make([]string, 0, len(k.VirtualKeys))
	for _, v := range k.VirtualKeys {
		ids = append(ids, v.ID.String())
	}
	return ids
}
