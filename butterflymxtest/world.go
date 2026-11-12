package butterflymxtest

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Seed lists the identifiers of the seeded world, so that tests can refer to
// them. The IDs reuse the fake IDs of the fixtures in testdata/.
type Seed struct {
	Email    string
	Password string

	ClientID    string
	RedirectURI string

	UserID       string // numeric, e.g. "563494348"
	UserGlobalID string // "prod-user-563494348"

	TenantID       string // numeric (REST), "7754340"
	TenantGlobalID string // "prod-tenant-7754340"
	UnitID         string
	UnitGlobalID   string
	UnitLabel      string
	BuildingID     string
	BuildingGID    string // "prod-building-78323"
	BuildingGUID   string // "prod-core-na-building-78323"
	BuildingName   string
	TimeZone       string // IANA zone of the building
	// VirtualKeysDurationDays is the longest allowed pass, in days.
	VirtualKeysDurationDays int

	AccessPoints []SeedAccessPoint
	Devices      []SeedDevice

	// ActiveKeychainIDs are the seeded passes that are active at seed time
	// (guest passes and one delivery pass), newest end first.
	ActiveKeychainIDs []string
	// DeliveryPassID is the seeded active delivery pass.
	DeliveryPassID string
	// ExpiredKeychainIDs are the seeded expired passes, newest end first.
	ExpiredKeychainIDs []string
}

// AccessPointByName returns the seeded access point called name.
func (sd Seed) AccessPointByName(name string) (SeedAccessPoint, bool) {
	for _, a := range sd.AccessPoints {
		if a.Name == name {
			return a, true
		}
	}
	return SeedAccessPoint{}, false
}

// VirtualKeyAccessPoints returns the seeded access points that can be used for
// guest passes (those with the VIRTUAL_KEYS capability).
func (sd Seed) VirtualKeyAccessPoints() []SeedAccessPoint {
	var out []SeedAccessPoint
	for _, a := range sd.AccessPoints {
		if a.VirtualKeys {
			out = append(out, a)
		}
	}
	return out
}

// SeedAccessPoint is a seeded door.
type SeedAccessPoint struct {
	ID          string // numeric (REST) id, also GraphQL legacyId
	GlobalID    string // "prod-access_point-70001"
	Name        string
	VirtualKeys bool // has the VIRTUAL_KEYS capability
	// DeviceGlobalID is the GraphQL id of the device behind the door.
	DeviceGlobalID string
}

// SeedDevice is a seeded intercom panel or cloud access controller.
type SeedDevice struct {
	GlobalID string // GraphQL id
	RESTID   string // /v3 id
	RESTType string // "panels" or "cloud_keyz_controllers"
	Name     string
}

// Keychain is a snapshot of a pass (keychain) held by the fake.
type Keychain struct {
	ID       string
	Name     string
	Kind     string // custom, recurring or delivery_pass
	TenantID string
	StartsAt time.Time
	EndsAt   time.Time
	// StartDate, EndDate, TimeFrom and TimeTo are the building-local
	// representation (YYYY-MM-DD and HH:MM).
	StartDate, EndDate string
	TimeFrom, TimeTo   string
	Weekdays           []string
	AccessPointIDs     []string
	VirtualKeys        []VirtualKey
}

// VirtualKey is a snapshot of a credential inside a keychain.
type VirtualKey struct {
	ID        string
	Name      string
	Email     string // empty when not delivered by email
	SMSNumber string // E.164, empty when not delivered by SMS
	PIN       string
	// SentAt is zero until the simulated asynchronous delivery has happened
	// (it happens on the first read after creation).
	SentAt time.Time
	// UsedAt is zero unless a one-time (delivery pass) key has been used.
	UsedAt time.Time
}

// Delivery is an email or SMS the fake "sent" for a virtual key.
type Delivery struct {
	KeychainID   string
	VirtualKeyID string
	Name         string
	Channel      string // "email" or "sms"
	To           string // address or E.164 number
	PIN          string
	// InstructionsURL is the guest page link the message would contain.
	InstructionsURL string
	QueuedAt        time.Time
	// SentAt is zero until the simulated delivery completed.
	SentAt time.Time
}

// Unlock is one call to the unlock service.
type Unlock struct {
	RequestID     string
	AccessPointID string // global id as sent
	TenantID      string // global id as sent
	Source        string
	At            time.Time
}

// ---- internal model ------------------------------------------------------

type accessPoint struct {
	id            string
	name          string
	caps          []string
	openDuration  int
	dev           *device
	readerSerials []string
}

func (a *accessPoint) hasCap(c string) bool { return slices.Contains(a.caps, c) }
func (a *accessPoint) gid() string          { return "prod-access_point-" + a.id }

type device struct {
	gqlType  string // Intercom | CloudBasedAccessController
	gqlID    string
	restType string // panels | cloud_keyz_controllers
	restID   string
	name     string
	serial   string // intercoms
}

func (d *device) gid() string {
	if d.gqlType == "Intercom" {
		return "prod-intercom-" + d.gqlID
	}
	return "prod-cloud_based_access_controller-" + d.gqlID
}

type virtualKey struct {
	id, name, email, sms, pin string
	qrURL, instrURL           string
	sentAt, usedAt            time.Time
	queued                    bool // delivery pending
	delivery                  *Delivery
}

type keychain struct {
	id, name, kind, tenantID string
	startsAt, endsAt         time.Time
	startDate, endDate       string
	timeFrom, timeTo         string
	weekdays                 []string
	allowUnit                bool
	apIDs                    []string
	vks                      []*virtualKey
}

type doorRelease struct {
	restID    string // /v3 id
	gqlNum    string // number in "prod-door_relase-N"
	cursorID  string
	at        time.Time
	apID      string
	gqlMethod string
	restMeth  string
	gqlType   string
	restType  string
	vkID      string
	name      string
	imageURL  string
}

type callRec struct {
	num, guid, imageURL, notif, status string
	at                                 time.Time
}

type messageRec struct {
	num, title, body, logoURL, imageURL string
	at                                  time.Time
}

type pushDevice struct {
	id, token, voip, description, version string
	locales                               []string
	development                           bool
}

type world struct {
	seed Seed
	loc  *time.Location

	aps  []*accessPoint
	devs []*device

	keychains []*keychain
	releases  []*doorRelease
	calls     []*callRec
	messages  []*messageRec
	push      map[string]*pushDevice

	deliveries []*Delivery
	unlocks    []Unlock

	used  map[string]bool
	imgN  int
	maxVK int // virtualKeysDurationPeriod
}

const (
	userID     = "563494348"
	tenantID   = "7754340"
	unitID     = "7761820"
	buildingID = "78323"
	tzName     = "America/Los_Angeles"
)

func (s *Server) seedWorld() *world {
	loc, err := time.LoadLocation(tzName)
	if err != nil {
		panic("butterflymxtest: " + err.Error())
	}
	w := &world{loc: loc, push: map[string]*pushDevice{}, used: map[string]bool{}, maxVK: 365}
	s.w = w // the seeding helpers go through s.w

	ctrlBike := &device{gqlType: "CloudBasedAccessController", gqlID: "51415", restType: "cloud_keyz_controllers", restID: "50410", name: "Bike Room & Garage Gate"}
	ctrlFront := &device{gqlType: "CloudBasedAccessController", gqlID: "37363", restType: "cloud_keyz_controllers", restID: "18461", name: "Front Door & Stairwell Door"}
	ctrlSide := &device{gqlType: "CloudBasedAccessController", gqlID: "28848", restType: "cloud_keyz_controllers", restID: "13673", name: "Side Door"}
	panel := &device{gqlType: "Intercom", gqlID: "86254", restType: "panels", restID: "38211", name: "Main Entrance", serial: "I484-09857228"}
	ctrlRoof := &device{gqlType: "CloudBasedAccessController", gqlID: "44010", restType: "cloud_keyz_controllers", restID: "44011", name: "Roof Terrace"}
	w.devs = []*device{ctrlBike, ctrlFront, ctrlSide, panel, ctrlRoof}

	vkCaps := []string{"BLUETOOTH", "DOOR_PINS", "SWIPE_TO_OPEN", "VIRTUAL_KEYS"}
	w.aps = []*accessPoint{
		{id: "51380", name: "Bike Room", caps: vkCaps, openDuration: 8, dev: ctrlBike, readerSerials: []string{"47790840536P5V4U"}},
		{id: "85679", name: "Garage Gate", caps: vkCaps, openDuration: 8, dev: ctrlBike, readerSerials: []string{}},
		{id: "27188", name: "Stairwell Door", caps: vkCaps, openDuration: 8, dev: ctrlFront, readerSerials: []string{"24522633540Y5T78"}},
		{id: "28821", name: "Main Entrance", caps: vkCaps, openDuration: 9, dev: panel},
		{id: "61152", name: "Side Door", caps: vkCaps, openDuration: 8, dev: ctrlSide, readerSerials: []string{"75538039711O9T98"}},
		{id: "12921", name: "Front Door", caps: vkCaps, openDuration: 8, dev: ctrlFront, readerSerials: []string{"14712280125G0R40"}},
		// No VIRTUAL_KEYS: lets tests exercise the capability validation.
		{id: "44001", name: "Roof Terrace", caps: []string{"BLUETOOTH", "SWIPE_TO_OPEN"}, openDuration: 8, dev: ctrlRoof, readerSerials: []string{}},
	}

	sd := Seed{
		Email: DefaultEmail, Password: DefaultPassword,
		ClientID: ClientID, RedirectURI: RedirectURI,
		UserID: userID, UserGlobalID: "prod-user-" + userID,
		TenantID: tenantID, TenantGlobalID: "prod-tenant-" + tenantID,
		UnitID: unitID, UnitGlobalID: "prod-unit-" + unitID, UnitLabel: "4B",
		BuildingID: buildingID, BuildingGID: "prod-building-" + buildingID, BuildingGUID: "prod-core-na-building-" + buildingID,
		BuildingName: "Example Tower", TimeZone: tzName, VirtualKeysDurationDays: w.maxVK,
	}
	for _, a := range w.aps {
		sd.AccessPoints = append(sd.AccessPoints, SeedAccessPoint{
			ID: a.id, GlobalID: a.gid(), Name: a.name, VirtualKeys: a.hasCap("VIRTUAL_KEYS"), DeviceGlobalID: a.dev.gid(),
		})
	}
	for _, d := range w.devs {
		sd.Devices = append(sd.Devices, SeedDevice{GlobalID: d.gid(), RESTID: d.restID, RESTType: d.restType, Name: d.name})
	}
	w.seed = sd

	s.seedPasses(w)
	s.seedHistory(w)
	return w
}

func (w *world) ap(id string) *accessPoint {
	for _, a := range w.aps {
		if a.id == id {
			return a
		}
	}
	return nil
}

func (w *world) keychain(id string) *keychain {
	for _, k := range w.keychains {
		if k.id == id {
			return k
		}
	}
	return nil
}

func (w *world) findVK(id string) (*keychain, *virtualKey) {
	for _, k := range w.keychains {
		for _, v := range k.vks {
			if v.id == id {
				return k, v
			}
		}
	}
	return nil, nil
}

func (w *world) newImageURL() string {
	w.imgN++
	return fmt.Sprintf("https://example.com/images/%d.jpg", w.imgN)
}

// ---- keychain derivation ---------------------------------------------------

const (
	instantLayout = "2006-01-02T15:04:05Z"
	dateLayout    = "2006-01-02"
	clockLayout   = "15:04"
)

func fmtInstant(t time.Time) string { return t.UTC().Format(instantLayout) }

func fmtOptInstant(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return fmtInstant(t)
}

// parseInstant accepts RFC 3339 and the "-0800" numeric-offset form the app
// sends when extending a delivery pass.
func parseInstant(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse("2006-01-02T15:04:05Z0700", s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

// fromInstants fills the building-local fields from starts_at and ends_at
// (spec §7.2, custom and delivery passes).
func (k *keychain) fromInstants(loc *time.Location) {
	k.startDate = k.startsAt.In(loc).Format(dateLayout)
	k.timeFrom = k.startsAt.In(loc).Format(clockLayout)
	k.endDate = k.endsAt.In(loc).Format(dateLayout)
	k.timeTo = k.endsAt.In(loc).Format(clockLayout)
}

// fromLocal fills starts_at and ends_at from the building-local fields (spec
// §7.2, recurring passes).
func (k *keychain) fromLocal(loc *time.Location) error {
	a, err := time.ParseInLocation(dateLayout+" "+clockLayout, k.startDate+" "+k.timeFrom, loc)
	if err != nil {
		return err
	}
	b, err := time.ParseInLocation(dateLayout+" "+clockLayout, k.endDate+" "+k.timeTo, loc)
	if err != nil {
		return err
	}
	k.startsAt, k.endsAt = a.UTC(), b.UTC()
	return nil
}

// expired reports whether the pass is in the "expired" list at now: it ended,
// or it is a delivery pass whose one-time key was used.
func (k *keychain) expired(now time.Time) bool {
	if !k.endsAt.After(now) {
		return true
	}
	if k.kind == "delivery_pass" {
		for _, v := range k.vks {
			if !v.usedAt.IsZero() {
				return true
			}
		}
	}
	return false
}

// devices returns the distinct devices behind the pass's access points, in
// order of first appearance.
func (w *world) devices(k *keychain) []*device {
	var out []*device
	for _, id := range k.apIDs {
		a := w.ap(id)
		if a != nil && !slices.Contains(out, a.dev) {
			out = append(out, a.dev)
		}
	}
	return out
}

// ---- virtual keys ------------------------------------------------------------

func (s *Server) newPIN() string {
	pins := map[string]bool{}
	for _, k := range s.w.keychains {
		for _, v := range k.vks {
			pins[v.pin] = true
		}
	}
	for {
		p := fmt.Sprintf("%06d", s.rnd.IntN(1_000_000))
		if !pins[p] {
			return p
		}
	}
}

const b36 = "0123456789abcdefghijklmnopqrstuvwxyz"

func (s *Server) newVirtualKey(name, email, sms string) *virtualKey {
	return s.mkVirtualKey(s.randID(8, s.w.used), s.newPIN(), name, email, sms)
}

func (s *Server) mkVirtualKey(id, pin, name, email, sms string) *virtualKey {
	padded := fmt.Sprintf("%09s", id)
	suffix := make([]byte, 6)
	for i := range suffix {
		suffix[i] = b36[s.rnd.IntN(len(b36))]
	}
	return &virtualKey{
		id: id, name: name, email: email, sms: sms, pin: pin,
		qrURL: fmt.Sprintf("https://s3.dualstack.us-east-1.amazonaws.com/bmx-rails-production/system/qr_keys/qr_code_images/%s/%s/%s/original/qr_code_%s-1-%s.png",
			padded[0:3], padded[3:6], padded[6:9], s.now().Format("20060102"), suffix),
		instrURL: fmt.Sprintf("https://user.butterflymx.com/public/virtual_keys/%s/%s", id, randHex(16)),
	}
}

// recipient is one entry of the "recipients" attribute.
type recipient struct {
	Name      string `json:"name"`
	DeliverTo string `json:"deliver_to"`
}

var errBadDeliverTo = errors.New("must be an email address or a phone number")

// classifyDeliverTo returns ("email", addr) or ("sms", e164).
func classifyDeliverTo(s string) (channel, to string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", errors.New("can't be blank")
	}
	if strings.Contains(s, "@") {
		at := strings.LastIndex(s, "@")
		dom := s[at+1:]
		if at == 0 || !strings.Contains(dom, ".") || strings.ContainsAny(s, " ,;<>") || strings.HasSuffix(dom, ".") {
			return "", "", errBadDeliverTo
		}
		return "email", s, nil
	}
	var digits strings.Builder
	plus := strings.HasPrefix(s, "+")
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits.WriteRune(r)
		case strings.ContainsRune(" ()-.+", r):
		default:
			return "", "", errBadDeliverTo
		}
	}
	d := digits.String()
	switch {
	case plus && len(d) >= 8 && len(d) <= 15:
		return "sms", "+" + d, nil
	case !plus && len(d) == 10:
		return "sms", "+1" + d, nil
	case !plus && len(d) == 11 && d[0] == '1':
		return "sms", "+" + d, nil
	}
	return "", "", errBadDeliverTo
}

// addRecipientKeys creates the virtual keys for already validated recipients
// and queues their deliveries.
func (s *Server) addRecipientKeys(k *keychain, rs []recipient) []*virtualKey {
	var out []*virtualKey
	for _, r := range rs {
		ch, to, _ := classifyDeliverTo(r.DeliverTo)
		name := strings.TrimSpace(r.Name)
		if name == "" {
			name = to
		}
		var vk *virtualKey
		if ch == "email" {
			vk = s.newVirtualKey(name, to, "")
		} else {
			vk = s.newVirtualKey(name, "", to)
		}
		vk.queued = true
		d := &Delivery{
			KeychainID: k.id, VirtualKeyID: vk.id, Name: name, Channel: ch, To: to,
			PIN: vk.pin, InstructionsURL: vk.instrURL, QueuedAt: s.now(),
		}
		vk.delivery = d
		s.w.deliveries = append(s.w.deliveries, d)
		k.vks = append(k.vks, vk)
		out = append(out, vk)
	}
	return out
}

// flushDeliveries simulates asynchronous delivery: keys queued before this
// read are marked as sent now.
func (s *Server) flushDeliveries() {
	now := s.now()
	for _, k := range s.w.keychains {
		for _, v := range k.vks {
			if v.queued {
				v.queued = false
				v.sentAt = now
				if v.delivery != nil {
					v.delivery.SentAt = now
				}
			}
		}
	}
}

// ---- exported accessors ------------------------------------------------------

// Seed returns the identifiers of the seeded world.
func (s *Server) Seed() Seed {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.seed
}

// Keychains returns snapshots of all passes currently held, in creation order.
func (s *Server) Keychains() []Keychain {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Keychain, 0, len(s.w.keychains))
	for _, k := range s.w.keychains {
		out = append(out, snapshot(k))
	}
	return out
}

func snapshot(k *keychain) Keychain {
	kc := Keychain{
		ID: k.id, Name: k.name, Kind: k.kind, TenantID: k.tenantID,
		StartsAt: k.startsAt, EndsAt: k.endsAt,
		StartDate: k.startDate, EndDate: k.endDate, TimeFrom: k.timeFrom, TimeTo: k.timeTo,
		Weekdays:       slices.Clone(k.weekdays),
		AccessPointIDs: slices.Clone(k.apIDs),
	}
	for _, v := range k.vks {
		kc.VirtualKeys = append(kc.VirtualKeys, VirtualKey{
			ID: v.id, Name: v.name, Email: v.email, SMSNumber: v.sms, PIN: v.pin, SentAt: v.sentAt, UsedAt: v.usedAt,
		})
	}
	return kc
}

// SentDeliveries returns every email or SMS the fake has "sent" (queued) for
// virtual keys, in order. Delivery passes send nothing.
func (s *Server) SentDeliveries() []Delivery {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Delivery, 0, len(s.w.deliveries))
	for _, d := range s.w.deliveries {
		out = append(out, *d)
	}
	return out
}

// Unlocks returns the calls made to the unlock service, in order.
func (s *Server) Unlocks() []Unlock {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.w.unlocks)
}

// AddDoorRelease simulates the use of a virtual key at a door: virtualKeyID
// and accessPointID are numeric (REST) ids. It logs a door release (visible
// through the keychain's virtual_keys.door_releases and the GraphQL door
// release history), and for a delivery pass key it marks the key as used
// (used_at and one_time_key_used_at) and ends the pass. The key's validity
// window is not enforced, but the door must be one of the pass's doors.
func (s *Server) AddDoorRelease(virtualKeyID, accessPointID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, vk := s.w.findVK(virtualKeyID)
	if vk == nil {
		return fmt.Errorf("butterflymxtest: unknown virtual key %q", virtualKeyID)
	}
	a := s.w.ap(accessPointID)
	if a == nil {
		return fmt.Errorf("butterflymxtest: unknown access point %q", accessPointID)
	}
	if !slices.Contains(k.apIDs, a.id) {
		return fmt.Errorf("butterflymxtest: access point %q is not part of keychain %q", accessPointID, k.id)
	}
	now := s.now()
	r := s.newRelease(now, a, "VIRTUAL_KEY_PIN", "virtual_key_pin", "VISITOR", "visitor", vk.id, vk.name)
	if k.kind == "delivery_pass" {
		r.restMeth, r.restType, r.gqlType = "delivery_pass", "delivery", "DELIVERY"
		vk.usedAt = now
		if k.endsAt.After(now) {
			k.endsAt = now
			k.fromInstants(s.w.loc)
		}
	}
	return nil
}

func (s *Server) newRelease(at time.Time, a *accessPoint, gqlMethod, restMethod, gqlType, restType, vkID, name string) *doorRelease {
	r := &doorRelease{
		restID: s.randID(10, s.w.used), gqlNum: s.randID(10, s.w.used), cursorID: randHex(12),
		at: at, apID: a.id, gqlMethod: gqlMethod, restMeth: restMethod, gqlType: gqlType, restType: restType,
		vkID: vkID, name: name, imageURL: s.w.newImageURL(),
	}
	s.w.releases = append(s.w.releases, r)
	return r
}

func (r *doorRelease) gid() string { return "prod-door_relase-" + r.gqlNum }
