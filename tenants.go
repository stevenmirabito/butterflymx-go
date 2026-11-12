package butterflymx

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"iter"
	"net/http"
	"slices"
	"time"

	"github.com/stevenmirabito/butterflymx-go/internal/graphql"
)

// Building capability names (Building.Capabilities) seen in captured traffic.
// Unknown capabilities are kept verbatim.
const (
	BuildingCapabilityVirtualKeys  = "VIRTUAL_KEYS_ENABLED"
	BuildingCapabilityDeliveryPass = "DELIVERY_PASS_ENABLED"
	BuildingCapabilityDoorPIN      = "DOOR_PIN_ENABLED"
	BuildingCapabilityBLEAccess    = "BLE_ACCESS_ENABLED"
)

// Tenant is a resident's tenancy: a unit in a building. Most operations are
// scoped to a tenant.
type Tenant struct {
	ID        GlobalID // "prod-tenant-..."; the numeric part is the REST tenant ID
	FirstName string
	LastName  string
	Name      string
	// PIN is the tenant's door PIN. It keeps leading zeros ("012345").
	PIN PIN
	// LegacyPIN is the older door PIN, if any.
	LegacyPIN PIN
	// InactiveAfter is when the tenancy ends, or nil.
	InactiveAfter *time.Time
	AwayMessage   string

	DeliveryPassEnabled        bool
	VirtualKeyEnabled          bool
	PrivacyConsentGiven        bool
	VirtualFobEntryEnabled     bool
	GeofenceEnabled            bool
	MaintenanceRequestsEnabled bool

	Unit                   Unit
	Building               Building
	NotificationPreference NotificationPreference
}

// CanCreateGuestPasses reports whether guest passes (virtual keys) can be
// created for this tenant: the tenant has virtual keys enabled, the building
// has the VIRTUAL_KEYS_ENABLED capability and is not suspended. This rule is
// inferred, not documented by ButterflyMX.
func (t Tenant) CanCreateGuestPasses() bool {
	return t.VirtualKeyEnabled && t.Building.HasCapability(BuildingCapabilityVirtualKeys) && !t.Building.Suspended
}

// Unit is an apartment or suite.
type Unit struct {
	ID          GlobalID
	Label       string
	FloorNumber string // a string on the wire
}

// Building is a building as seen by a tenant.
type Building struct {
	ID   GlobalID
	GUID string // a different ID scheme, for example "prod-core-na-building-78323"
	Name string
	// Country is the lowercase country code of the address, for example "us".
	Country string
	// TimeZone is an IANA zone name, for example "America/Los_Angeles".
	TimeZone string
	// Capabilities lists building feature flags such as VIRTUAL_KEYS_ENABLED.
	Capabilities        []string
	EnabledIntegrations []string
	ContactLabel        string
	ContactPhoneNumber  string
	// VirtualKeysDurationPeriod is the guest-pass duration limit in days (the
	// exact meaning is inferred; the app reports 365).
	VirtualKeysDurationPeriod int
	Suspended                 bool
	Geofence                  *Geofence
	// AmenityReservationsFeeStrategy is for example "RECORD_PAYMENTS".
	AmenityReservationsFeeStrategy string
}

// Location loads the building's time zone.
func (b Building) Location() (*time.Location, error) {
	return time.LoadLocation(b.TimeZone)
}

// HasCapability reports whether the building has capability c.
func (b Building) HasCapability(c string) bool { return slices.Contains(b.Capabilities, c) }

// Geofence is a circular area around a building.
type Geofence struct {
	ID              GlobalID
	CenterLatitude  float64
	CenterLongitude float64
	RadiusValue     float64
	RadiusUnit      string
}

// NotificationPreference holds a tenant's notification settings. Values are
// raw API strings such as "VIDEO_CALL", "NOTIFICATION" and "SMS".
type NotificationPreference struct {
	Call         string
	DoNotDisturb bool
	DoorOpen     []string
	Message      []string
}

type gqlGeofenceWire struct {
	ID              GlobalID `json:"id"`
	CenterLatitude  float64  `json:"centerLatitude"`
	CenterLongitude float64  `json:"centerLongitude"`
	RadiusUnit      string   `json:"radiusUnit"`
	RadiusValue     float64  `json:"radiusValue"`
}

type gqlBuildingWire struct {
	ID      GlobalID `json:"id"`
	GUID    string   `json:"guid"`
	Name    string   `json:"name"`
	Address struct {
		Country string `json:"country"`
	} `json:"address"`
	Capabilities                   []string         `json:"capabilities"`
	EnabledIntegrations            []string         `json:"enabledIntegrations"`
	ContactLabel                   string           `json:"contactLabel"`
	ContactPhoneNumber             string           `json:"contactPhoneNumber"`
	TimeZone                       string           `json:"timeZone"`
	AmenityReservationsFeeStrategy string           `json:"amenityReservationsFeeStrategy"`
	VirtualKeysDurationPeriod      int              `json:"virtualKeysDurationPeriod"`
	Geofence                       *gqlGeofenceWire `json:"geofence"`
	Suspended                      bool             `json:"suspended"`
}

func (w gqlBuildingWire) convert() Building {
	b := Building{
		ID: w.ID, GUID: w.GUID, Name: w.Name, Country: w.Address.Country, TimeZone: w.TimeZone,
		Capabilities: w.Capabilities, EnabledIntegrations: w.EnabledIntegrations,
		ContactLabel: w.ContactLabel, ContactPhoneNumber: w.ContactPhoneNumber,
		VirtualKeysDurationPeriod:      w.VirtualKeysDurationPeriod,
		Suspended:                      w.Suspended,
		AmenityReservationsFeeStrategy: w.AmenityReservationsFeeStrategy,
	}
	if g := w.Geofence; g != nil {
		b.Geofence = &Geofence{ID: g.ID, CenterLatitude: g.CenterLatitude, CenterLongitude: g.CenterLongitude,
			RadiusValue: g.RadiusValue, RadiusUnit: g.RadiusUnit}
	}
	return b
}

type gqlTenantWire struct {
	ID            GlobalID `json:"id"`
	FirstName     string   `json:"firstName"`
	LastName      string   `json:"lastName"`
	Name          string   `json:"name"`
	InactiveAfter *string  `json:"inactiveAfter"`
	AwayMessage   string   `json:"awayMessage"`
	PinCode       string   `json:"pinCode"`
	LegacyPinCode string   `json:"legacyPinCode"`

	DeliveryPassEnabled        bool `json:"deliveryPassEnabled"`
	VirtualKeyEnabled          bool `json:"virtualKeyEnabled"`
	PrivacyConsentGiven        bool `json:"privacyConsentGiven"`
	VirtualFobEntryEnabled     bool `json:"virtualFobEntryEnabled"`
	GeofenceEnabled            bool `json:"geofenceEnabled"`
	MaintenanceRequestsEnabled bool `json:"maintenanceRequestsEnabled"`

	Unit struct {
		ID          GlobalID `json:"id"`
		Label       string   `json:"label"`
		FloorNumber string   `json:"floorNumber"`
	} `json:"unit"`
	Building               gqlBuildingWire `json:"building"`
	NotificationPreference struct {
		Call         string   `json:"call"`
		DoNotDisturb bool     `json:"doNotDisturb"`
		DoorOpen     []string `json:"doorOpen"`
		Message      []string `json:"message"`
	} `json:"notificationPreference"`
}

func (w gqlTenantWire) convert() Tenant {
	return Tenant{
		ID: w.ID, FirstName: w.FirstName, LastName: w.LastName, Name: w.Name,
		PIN: PIN(w.PinCode), LegacyPIN: PIN(w.LegacyPinCode),
		InactiveAfter: gqlTimePtr(w.InactiveAfter), AwayMessage: w.AwayMessage,
		DeliveryPassEnabled: w.DeliveryPassEnabled, VirtualKeyEnabled: w.VirtualKeyEnabled,
		PrivacyConsentGiven: w.PrivacyConsentGiven, VirtualFobEntryEnabled: w.VirtualFobEntryEnabled,
		GeofenceEnabled: w.GeofenceEnabled, MaintenanceRequestsEnabled: w.MaintenanceRequestsEnabled,
		Unit:     Unit{ID: w.Unit.ID, Label: w.Unit.Label, FloorNumber: w.Unit.FloorNumber},
		Building: w.Building.convert(),
		NotificationPreference: NotificationPreference{
			Call: w.NotificationPreference.Call, DoNotDisturb: w.NotificationPreference.DoNotDisturb,
			DoorOpen: w.NotificationPreference.DoorOpen, Message: w.NotificationPreference.Message,
		},
	}
}

// Tenants returns every tenancy of the signed-in user, following pagination.
func (c *Client) Tenants(ctx context.Context) ([]Tenant, error) {
	const op = "Tenants"
	seq := graphql.Pages(ctx, func(ctx context.Context, after string) ([]Tenant, graphql.PageInfo, error) {
		var data struct {
			Tenants *graphql.Connection[gqlTenantWire] `json:"tenants"`
		}
		if err := c.graphQL(ctx, op, graphql.Tenants, gqlAfterVars(nil, after), &data); err != nil {
			return nil, graphql.PageInfo{}, err
		}
		if data.Tenants == nil {
			return nil, graphql.PageInfo{}, nil
		}
		out := make([]Tenant, len(data.Tenants.Nodes))
		for i, n := range data.Tenants.Nodes {
			out[i] = n.convert()
		}
		return out, data.Tenants.PageInfo, nil
	})
	return gqlCollect(seq)
}

// Tenant returns one tenancy. If the tenant does not exist or is not
// accessible, the error satisfies errors.Is(err, ErrNotFound).
func (c *Client) Tenant(ctx context.Context, id GlobalID) (*Tenant, error) {
	const op = "Tenant"
	if err := gqlCheckID(op, id, TypeTenant); err != nil {
		return nil, err
	}
	var data struct {
		Nodes []*gqlTenantWire `json:"nodes"`
	}
	if err := c.graphQL(ctx, op, graphql.Tenant, map[string]any{"tenantId": id.String()}, &data); err != nil {
		return nil, err
	}
	if len(data.Nodes) == 0 || data.Nodes[0] == nil || data.Nodes[0].ID.IsZero() {
		return nil, gqlNotFound(op, "tenant "+id.String())
	}
	t := data.Nodes[0].convert()
	return &t, nil
}

// ---- shared helpers (used by the other GraphQL files) ----------------------

// gqlNotFound returns an *Error that satisfies errors.Is(err, ErrNotFound).
func gqlNotFound(op, what string) error {
	return &Error{Op: op, Method: http.MethodPost, URL: graphQLPath,
		Err: fmt.Errorf("%w: %s", ErrNotFound, what)}
}

// gqlCheckID returns an error wrapping ErrIDType unless id has type tag typ.
func gqlCheckID(op string, id GlobalID, typ string) error {
	if _, err := id.As(typ); err != nil {
		return &Error{Op: op, Err: err}
	}
	return nil
}

func gqlAfterVars(vars map[string]any, after string) map[string]any {
	if vars == nil {
		vars = map[string]any{}
	}
	if after != "" {
		vars["after"] = after
	}
	return vars
}

// gqlTime parses an API timestamp leniently; unparsable input yields the zero time.
func gqlTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := parseInstant(s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func gqlTimePtr(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := parseInstant(*s)
	if err != nil {
		return nil
	}
	return &t
}

// gqlTenantField runs a query of the shape nodes(ids:[tenant]) { ... on Tenant
// { <field> ... } } and returns the raw value of field. ok is false when the
// tenant node is null or lacks the field.
func (c *Client) gqlTenantField(ctx context.Context, op string, gop graphql.Operation, vars map[string]any, field string) (raw jsontext.Value, found bool, err error) {
	var data struct {
		Nodes []map[string]jsontext.Value `json:"nodes"`
	}
	if err := c.graphQL(ctx, op, gop, vars, &data); err != nil {
		return nil, false, err
	}
	if len(data.Nodes) == 0 || data.Nodes[0] == nil {
		return nil, false, nil
	}
	raw, found = data.Nodes[0][field]
	return raw, found, nil
}

// gqlConnPages iterates over the Relay connection field of a tenant node,
// converting each wire node with conv. Validation of tenantID is the caller's
// job.
func gqlConnPages[W, T any](ctx context.Context, c *Client, op string, gop graphql.Operation, idVar string,
	tenantID GlobalID, extra map[string]any, field string, conv func(W) (T, bool)) iter.Seq2[T, error] {
	return graphql.Pages(ctx, func(ctx context.Context, after string) ([]T, graphql.PageInfo, error) {
		vars := gqlAfterVars(map[string]any{idVar: []string{tenantID.String()}}, after)
		for k, v := range extra {
			vars[k] = v
		}
		raw, found, err := c.gqlTenantField(ctx, op, gop, vars, field)
		if err != nil {
			return nil, graphql.PageInfo{}, err
		}
		if !found {
			return nil, graphql.PageInfo{}, gqlNotFound(op, "tenant "+tenantID.String())
		}
		if len(raw) == 0 || string(raw) == "null" {
			return nil, graphql.PageInfo{}, nil
		}
		var conn graphql.Connection[W]
		if err := json.Unmarshal(raw, &conn); err != nil {
			return nil, graphql.PageInfo{}, &Error{Op: op, Method: http.MethodPost, URL: graphQLPath,
				Err: fmt.Errorf("decode %s: %w", field, err)}
		}
		out := make([]T, 0, len(conn.Nodes))
		for _, n := range conn.Nodes {
			if v, ok := conv(n); ok {
				out = append(out, v)
			}
		}
		return out, conn.PageInfo, nil
	})
}

// gqlFailSeq is an iterator that yields only err.
func gqlFailSeq[T any](err error) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		var zero T
		yield(zero, err)
	}
}

// gqlCollect drains seq into a slice, stopping at the first error.
func gqlCollect[T any](seq iter.Seq2[T, error]) ([]T, error) {
	out := []T{}
	for v, err := range seq {
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// gqlScalar accepts a JSON string or number (or null) as a string. It
// protects against the API changing an ID between string and number.
type gqlScalar string

func (s *gqlScalar) UnmarshalJSON(b []byte) error {
	switch {
	case len(b) == 0 || string(b) == "null":
		*s = ""
	case b[0] == '"':
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*s = gqlScalar(v)
	default:
		*s = gqlScalar(b)
	}
	return nil
}
