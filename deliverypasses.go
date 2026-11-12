package butterflymx

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/stevenmirabito/butterflymx-go/internal/jsonapi"
)

// restDefaultDeliveryPassName is the name the app gives a new delivery pass.
const restDefaultDeliveryPassName = "Delivery Pass"

// DeliveryPassParams describes a new delivery pass.
type DeliveryPassParams struct {
	// TenantID is the tenant the pass belongs to; a tenant global ID.
	TenantID GlobalID
	// Name labels the pass (and its key); default "Delivery Pass".
	Name string
}

// CreateDeliveryPass creates a delivery pass (POST /v3/keychains/delivery_pass):
// a keychain with a single one-time virtual key and no recipient, valid for 30
// days or until first use. Delivery passes always cover every guest-pass door
// (every door that supports virtual keys): the server ignores access_points,
// so it is sent empty, as the app does, and there is no per-door option.
//
// Nothing is sent to anyone; show the key's PIN, QR code or instructions URL to the courier yourself.
//
// Like [Client.CreateKeychain] this is not idempotent and is never retried
// automatically; reconcile with [Client.Keychains] (filtering on
// [KindDeliveryPass]) after an ambiguous failure.
func (c *Client) CreateDeliveryPass(ctx context.Context, p DeliveryPassParams) (*Keychain, error) {
	const op = "CreateDeliveryPass"
	tenant, err := restTenantRel(p.TenantID)
	if err != nil {
		return nil, restFail(op, err)
	}
	name := strings.TrimSpace(p.Name)
	if name == "" {
		name = restDefaultDeliveryPassName
	}
	// Everything except the name is an explicit null, as the app sends it.
	doc, err := c.jsonAPI(ctx, op, http.MethodPost, "/v3/keychains/delivery_pass", nil, &jsonapi.ResourceObject{
		Type:       "keychains",
		Attributes: restKeychainWrite{Name: name},
		Relationships: map[string]jsonapi.RelationshipObject{
			"tenant":        tenant,
			"access_points": jsonapi.ToMany("access_points"),
			"virtual_keys":  jsonapi.ToMany("virtual_keys"),
			"devices":       jsonapi.ToMany("devices"),
		},
	})
	if err != nil {
		return nil, err
	}
	return restKeychainDoc(op, doc)
}

// DeliveryPassUpdate describes changes to a delivery pass; nil fields are kept.
type DeliveryPassUpdate struct {
	// Name renames the pass and its key.
	Name *string
	// EndsAt moves the end of the validity window. It must be after the
	// pass's start.
	EndsAt *time.Time
}

// UpdateDeliveryPass renames and/or extends a delivery pass.
//
// The API replaces the whole attribute set, so this reads the pass, merges the
// update, sends the full set the way the app does (PATCH
// /v3/keychains/delivery_pass/{id}, which answers 204 with no body) and then
// reads the pass again to return the result. The stale end_date from the read
// is sent unchanged: the server derives it from ends_at, which takes
// precedence (spec §7.4a). Instants are sent in UTC (the app sends a numeric
// offset such as -0800; both denote the same instant).
//
// The id must belong to a delivery pass; otherwise the error wraps
// [ErrValidation].
func (c *Client) UpdateDeliveryPass(ctx context.Context, id ID, u DeliveryPassUpdate) (*Keychain, error) {
	const op = "UpdateDeliveryPass"
	if u.Name == nil && u.EndsAt == nil {
		return nil, restFail(op, restInvalid("nothing to update"))
	}
	return c.restUpdateDeliveryPass(ctx, op, id, func(cur *Keychain) (string, time.Time) {
		name, ends := cur.Name, cur.EndsAt
		if u.Name != nil {
			name = *u.Name
		}
		if u.EndsAt != nil {
			ends = *u.EndsAt
		}
		return name, ends
	})
}

// ExtendDeliveryPass moves a delivery pass's end by the given duration, from
// its current EndsAt (so 30*24*time.Hour reproduces the app's "extend 30
// days"). A negative duration shortens the pass. See [Client.UpdateDeliveryPass]
// for how the update is made.
func (c *Client) ExtendDeliveryPass(ctx context.Context, id ID, by time.Duration) (*Keychain, error) {
	return c.restUpdateDeliveryPass(ctx, "ExtendDeliveryPass", id, func(cur *Keychain) (string, time.Time) {
		return cur.Name, cur.EndsAt.Add(by)
	})
}

func (c *Client) restUpdateDeliveryPass(ctx context.Context, op string, id ID, merge func(cur *Keychain) (string, time.Time)) (*Keychain, error) {
	if id <= 0 {
		return nil, restFail(op, restInvalid("delivery pass id is required"))
	}
	cur, err := c.restGetKeychain(ctx, op, id)
	if err != nil {
		return nil, err
	}
	if cur.Kind != KindDeliveryPass {
		return nil, restFail(op, restInvalid("keychain %s is a %q pass, not a delivery pass", id, cur.Kind))
	}
	name, ends := merge(cur)
	if !c.cfg.SkipClientValidation {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, restFail(op, restInvalid("name must not be blank"))
		}
		if ends.IsZero() || !ends.Truncate(time.Second).After(cur.StartsAt.Truncate(time.Second)) {
			return nil, restFail(op, restInvalid("EndsAt (%s) must be after the pass start (%s)", formatInstant(ends), formatInstant(cur.StartsAt)))
		}
	}
	a := restReadAttrs(cur)
	a.Kind = restPtr(string(KindDeliveryPass))
	a.Name = name
	a.EndsAt = restPtr(formatInstant(ends))
	if _, err := c.jsonAPI(ctx, op, http.MethodPatch, "/v3/keychains/delivery_pass/"+id.String(), nil, &jsonapi.ResourceObject{
		Type:       "keychains",
		Attributes: a,
		Relationships: map[string]jsonapi.RelationshipObject{
			"tenant":        jsonapi.ToOneNull("tenants"),
			"virtual_keys":  jsonapi.ToMany("virtual_keys", restKeyIDs(cur)...),
			"access_points": jsonapi.ToMany("access_points"),
			"devices":       jsonapi.ToMany("devices"),
		},
	}); err != nil {
		return nil, err
	}
	return c.restGetKeychain(ctx, op, id)
}
