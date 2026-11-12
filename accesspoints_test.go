package butterflymx

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestGQLAccessPointsFixture(t *testing.T) {
	c, seen := gqlTestOps(t, map[string]func(map[string]any) []byte{"TenantAccessPoints": gqlTestFixture(t, "TenantAccessPoints")})
	tid, _ := ParseGlobalID("prod-tenant-7754340")
	aps, err := c.AccessPoints(context.Background(), tid)
	if err != nil {
		t.Fatal(err)
	}
	if len(aps) != 6 {
		t.Fatalf("len = %d", len(aps))
	}
	if ids, _ := (*seen)[0]["ids"].([]any); len(ids) != 1 || ids[0] != "prod-tenant-7754340" {
		t.Errorf("ids var = %v", (*seen)[0]["ids"])
	}
	a := aps[0]
	if a.ID.String() != "prod-access_point-51380" || a.LegacyID != 51380 || a.RESTID() != 51380 || a.Name != "Bike Room" {
		t.Errorf("ap = %+v", a)
	}
	if !a.SupportsVirtualKeys() || len(a.Capabilities) != 4 || a.Capabilities[0] != "BLUETOOTH" {
		t.Errorf("capabilities = %v", a.Capabilities)
	}
	if a.OpenDuration != 8*time.Second || !a.Online || a.InOpenHours {
		t.Errorf("flags = %+v", a)
	}
	if len(a.DoorOpenSchedules) != 0 || len(a.AccessTimes) != 1 {
		t.Fatalf("times = %+v / %+v", a.AccessTimes, a.DoorOpenSchedules)
	}
	r := a.AccessTimes[0]
	if r.From.String() != "00:00" || r.To.String() != "00:00" || len(r.Days) != 7 || r.Days[0] != Monday || r.Days[6] != Sunday {
		t.Errorf("restriction = %+v", r)
	}
	if a.Building.TimeZone != "America/Los_Angeles" || a.Building.ID.Num != 78323 {
		t.Errorf("building = %+v", a.Building)
	}
	if len(a.Devices) != 1 || a.Devices[0].Kind != "CloudBasedAccessController" || a.Devices[0].ID.Type != TypeCloudBasedAccessController ||
		len(a.Devices[0].ReaderSerialNumbers) != 1 || a.Devices[0].ReaderSerialNumbers[0] != "47790840536P5V4U" {
		t.Errorf("devices = %+v", a.Devices)
	}
	var intercom *AccessPoint
	for i := range aps {
		if aps[i].LegacyID == 28821 {
			intercom = &aps[i]
		}
	}
	if intercom == nil || len(intercom.Devices) != 1 || intercom.Devices[0].Kind != "Intercom" ||
		intercom.Devices[0].SerialNumber == "" || intercom.OpenDuration != 9*time.Second {
		t.Errorf("intercom ap = %+v", intercom)
	}
}

func TestGQLAccessPointHelpers(t *testing.T) {
	a := AccessPoint{ID: NewGlobalID("prod", TypeAccessPoint, 7), Capabilities: []string{"DOOR_PINS"}}
	if a.SupportsVirtualKeys() || a.RESTID() != 7 {
		t.Errorf("%+v", a)
	}
	a.LegacyID = 9
	a.Capabilities = append(a.Capabilities, "VIRTUAL_KEYS")
	if !a.SupportsVirtualKeys() || a.RESTID() != 9 {
		t.Errorf("%+v", a)
	}
}

func TestGQLAccessPointsErrors(t *testing.T) {
	c, seen := gqlTestOps(t, map[string]func(map[string]any) []byte{
		"TenantAccessPoints": func(map[string]any) []byte { return []byte(`{"data":{"nodes":[null]}}`) },
	})
	ctx := context.Background()
	if _, err := c.AccessPoints(ctx, NewGlobalID("prod", TypeAccessPoint, 1)); !errors.Is(err, ErrIDType) {
		t.Errorf("err = %v, want ErrIDType", err)
	}
	if len(*seen) != 0 {
		t.Errorf("requests = %d", len(*seen))
	}
	if _, err := c.AccessPoints(ctx, NewGlobalID("prod", TypeTenant, 1)); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestGQLTimeRestrictionLenient(t *testing.T) {
	got := gqlTimeRestrictions([]gqlTimeRestrictionWire{{From: "bad", To: "17:30", Days: []string{"MONDAY", "FUNDAY"}}})
	if len(got) != 1 || got[0].To.String() != "17:30" || got[0].Days[0] != Monday || got[0].Days[1] != Weekday("FUNDAY") {
		t.Errorf("got %+v", got)
	}
}
