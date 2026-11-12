package butterflymx

import (
	"context"
	"time"

	"github.com/stevenmirabito/butterflymx-go/internal/graphql"
)

// AccessPointCapabilityVirtualKeys is the AccessPoint capability that allows
// guest passes (virtual keys) for the door.
const AccessPointCapabilityVirtualKeys = "VIRTUAL_KEYS"

// AccessPoint is a door a tenant can open.
type AccessPoint struct {
	ID GlobalID // "prod-access_point-..."
	// LegacyID is the numeric REST ID ("legacyId" in GraphQL). It equals ID.Num.
	LegacyID ID
	Name     string
	// Capabilities are raw API strings, for example BLUETOOTH, DOOR_PINS,
	// SWIPE_TO_OPEN and VIRTUAL_KEYS.
	Capabilities []string
	// OpenDuration is how long the door stays unlocked after an unlock. The
	// API sends a bare integer; this library assumes seconds (unverified).
	OpenDuration time.Duration
	Online       bool
	InOpenHours  bool
	// AccessTimes are the windows when the tenant may use the door. A single
	// 00:00-00:00 window on all days means always.
	AccessTimes []TimeRestriction
	// DoorOpenSchedules are the windows when the door is held open.
	DoorOpenSchedules []TimeRestriction
	Building          Building
	Devices           []Device
}

// SupportsVirtualKeys reports whether guest passes can include this door.
func (a AccessPoint) SupportsVirtualKeys() bool {
	for _, c := range a.Capabilities {
		if c == AccessPointCapabilityVirtualKeys {
			return true
		}
	}
	return false
}

// RESTID returns the numeric ID used by the REST API: LegacyID if set, else
// the numeric part of ID.
func (a AccessPoint) RESTID() ID {
	if a.LegacyID != 0 {
		return a.LegacyID
	}
	return a.ID.Num
}

// TimeRestriction is a recurring time window on certain weekdays. From == To
// (for example 00:00-00:00) with all days means the whole day.
type TimeRestriction struct {
	From, To TimeOfDay
	Days     []Weekday
}

// Device is the hardware behind an access point.
type Device struct {
	ID GlobalID
	// Kind is the GraphQL type name: "Intercom", "CloudBasedAccessController"
	// or another value for devices this library does not know.
	Kind string
	Name string
	// SerialNumber is set for intercoms.
	SerialNumber string
	// ReaderSerialNumbers is set for cloud-based access controllers.
	ReaderSerialNumbers []string
}

type gqlTimeRestrictionWire struct {
	From string   `json:"from"`
	To   string   `json:"to"`
	Days []string `json:"days"`
}

// gqlTimeRestrictions converts leniently: unparsable times become 00:00 and
// unknown weekdays are kept verbatim.
func gqlTimeRestrictions(in []gqlTimeRestrictionWire) []TimeRestriction {
	if len(in) == 0 {
		return nil
	}
	out := make([]TimeRestriction, len(in))
	for i, w := range in {
		r := TimeRestriction{}
		r.From, _ = ParseTimeOfDay(w.From)
		r.To, _ = ParseTimeOfDay(w.To)
		for _, d := range w.Days {
			if v, err := ParseWeekday(d); err == nil {
				r.Days = append(r.Days, v)
			} else {
				r.Days = append(r.Days, Weekday(d))
			}
		}
		out[i] = r
	}
	return out
}

type gqlAccessPointWire struct {
	ID                GlobalID                 `json:"id"`
	LegacyID          gqlScalar                `json:"legacyId"`
	Name              string                   `json:"name"`
	Capabilities      []string                 `json:"capabilities"`
	OpenDuration      float64                  `json:"openDuration"`
	Online            bool                     `json:"online"`
	InOpenHours       bool                     `json:"inOpenHours"`
	DoorOpenSchedules []gqlTimeRestrictionWire `json:"doorOpenSchedules"`
	AccessTimes       []gqlTimeRestrictionWire `json:"accessTimes"`
	Building          gqlBuildingWire          `json:"building"`
	Devices           struct {
		Nodes []struct {
			Typename            string    `json:"__typename"`
			ID                  GlobalID  `json:"id"`
			Name                string    `json:"name"`
			SerialNumber        gqlScalar `json:"serialNumber"`
			ReaderSerialNumbers []string  `json:"readerSerialNumbers"`
		} `json:"nodes"`
	} `json:"devices"`
}

func (w gqlAccessPointWire) convert() (AccessPoint, bool) {
	if w.ID.IsZero() {
		return AccessPoint{}, false
	}
	a := AccessPoint{
		ID: w.ID, Name: w.Name, Capabilities: w.Capabilities,
		OpenDuration: time.Duration(w.OpenDuration * float64(time.Second)),
		Online:       w.Online, InOpenHours: w.InOpenHours,
		AccessTimes:       gqlTimeRestrictions(w.AccessTimes),
		DoorOpenSchedules: gqlTimeRestrictions(w.DoorOpenSchedules),
		Building:          w.Building.convert(),
	}
	if id, err := ParseID(string(w.LegacyID)); err == nil {
		a.LegacyID = id
	}
	for _, d := range w.Devices.Nodes {
		if d.ID.IsZero() {
			continue
		}
		a.Devices = append(a.Devices, Device{ID: d.ID, Kind: d.Typename, Name: d.Name,
			SerialNumber: string(d.SerialNumber), ReaderSerialNumbers: d.ReaderSerialNumbers})
	}
	return a, true
}

// AccessPoints returns every door of the tenant, following pagination. An
// unknown or inaccessible tenant yields an error satisfying
// errors.Is(err, ErrNotFound).
func (c *Client) AccessPoints(ctx context.Context, tenantID GlobalID) ([]AccessPoint, error) {
	const op = "TenantAccessPoints"
	if err := gqlCheckID(op, tenantID, TypeTenant); err != nil {
		return nil, err
	}
	return gqlCollect(gqlConnPages(ctx, c, op, graphql.TenantAccessPoints, "ids", tenantID, nil,
		"accessPoints", gqlAccessPointWire.convert))
}
