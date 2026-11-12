package butterflymx

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stevenmirabito/butterflymx-go/butterflymxtest"
)

func gqlTestGID(t *testing.T, s string) GlobalID {
	t.Helper()
	g, err := ParseGlobalID(s)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestGQLFakeReads(t *testing.T) {
	c, s := newFakeClient(t, butterflymxtest.WithPageSize(2))
	ctx := context.Background()
	seed := s.Seed()
	tid := gqlTestGID(t, seed.TenantGlobalID)

	u, err := c.CurrentUser(ctx)
	if err != nil || u.ID.String() != seed.UserGlobalID || u.Email != seed.Email {
		t.Fatalf("CurrentUser = %+v, %v", u, err)
	}
	ts, err := c.Tenants(ctx)
	if err != nil || len(ts) != 1 || ts[0].ID != tid {
		t.Fatalf("Tenants = %+v, %v", ts, err)
	}
	tn, err := c.Tenant(ctx, tid)
	if err != nil {
		t.Fatal(err)
	}
	if tn.Building.TimeZone != seed.TimeZone || tn.Unit.Label != seed.UnitLabel || tn.Building.Name != seed.BuildingName ||
		tn.Building.VirtualKeysDurationPeriod != seed.VirtualKeysDurationDays || !tn.CanCreateGuestPasses() || !tn.PIN.Valid() {
		t.Errorf("tenant = %+v", tn)
	}

	// Page size 2 forces three pages for the six seeded doors.
	aps, err := c.AccessPoints(ctx, tid)
	if err != nil {
		t.Fatal(err)
	}
	if len(aps) != len(seed.AccessPoints) {
		t.Fatalf("AccessPoints = %d, want %d", len(aps), len(seed.AccessPoints))
	}
	for i, a := range aps {
		want := seed.AccessPoints[i]
		if a.ID.String() != want.GlobalID || a.RESTID().String() != want.ID || a.Name != want.Name || a.SupportsVirtualKeys() != want.VirtualKeys {
			t.Errorf("ap[%d] = %+v, want %+v", i, a, want)
		}
		if len(a.Devices) == 0 || a.Devices[0].ID.String() != want.DeviceGlobalID {
			t.Errorf("ap[%d] devices = %+v", i, a.Devices)
		}
	}

	n := 0
	for d, err := range c.DoorReleases(ctx, tid) {
		if err != nil {
			t.Fatal(err)
		}
		if d.ID.IsZero() || d.LoggedAt.IsZero() || d.AccessPoint.ID.IsZero() {
			t.Fatalf("release = %+v", d)
		}
		n++
	}
	if n == 0 {
		t.Error("no door releases")
	}
	for _, err := range c.Calls(ctx, tid) {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, err := range c.Messages(ctx, tid, &MessageOptions{ImageSize: "medium"}) {
		if err != nil {
			t.Fatal(err)
		}
	}
	if sl, err := c.SmartLocks(ctx, tid, true); err != nil || len(sl) != 0 {
		t.Errorf("SmartLocks = %v, %v", sl, err)
	}
	if rl, err := c.RemoteLocks(ctx, tid); err != nil || len(rl) != 0 {
		t.Errorf("RemoteLocks = %v, %v", rl, err)
	}
	if lpr, err := c.LPRSettings(ctx, tid); err != nil || lpr == nil {
		t.Errorf("LPRSettings = %v, %v", lpr, err)
	}
	ble, err := c.BLECredentials(ctx, tid, NewGlobalID("prod", TypeUserDeviceApple, 65794426))
	if err != nil || ble.IntercomBLEDeviceKey == "" || ble.WavelynxKMD == "" {
		t.Errorf("BLECredentials = %+v, %v", ble, err)
	}
}

func TestGQLFakeErrors(t *testing.T) {
	c, s := newFakeClient(t)
	ctx := context.Background()
	other := NewGlobalID("prod", TypeTenant, 1)
	tid := gqlTestGID(t, s.Seed().TenantGlobalID)

	if _, err := c.Tenant(ctx, other); !errors.Is(err, ErrNotFound) {
		t.Errorf("Tenant unknown: %v", err)
	}
	if _, err := c.AccessPoints(ctx, other); !errors.Is(err, ErrNotFound) {
		t.Errorf("AccessPoints unknown: %v", err)
	}
	if _, err := c.LPRSettings(ctx, other); !errors.Is(err, ErrNotFound) {
		t.Errorf("LPRSettings unknown: %v", err)
	}
	for _, err := range c.DoorReleases(ctx, other) {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("DoorReleases unknown: %v", err)
		}
	}
	before := len(s.Requests())
	ap := NewGlobalID("prod", TypeAccessPoint, 1)
	if _, err := c.Tenant(ctx, ap); !errors.Is(err, ErrIDType) {
		t.Errorf("Tenant wrong type: %v", err)
	}
	if _, err := c.Unlock(ctx, ap, ap); !errors.Is(err, ErrIDType) {
		t.Errorf("Unlock wrong tenant type: %v", err)
	}
	if _, err := c.Unlock(ctx, tid, tid); !errors.Is(err, ErrIDType) {
		t.Errorf("Unlock wrong ap type: %v", err)
	}
	if len(s.Requests()) != before {
		t.Error("ID type errors must not send requests")
	}
}

func TestGQLFakeUnlock(t *testing.T) {
	c, s := newFakeClient(t)
	ctx := context.Background()
	seed := s.Seed()
	tid := gqlTestGID(t, seed.TenantGlobalID)
	ap := gqlTestGID(t, seed.AccessPoints[0].GlobalID)

	id, err := c.Unlock(ctx, tid, ap)
	if err != nil || id == "" {
		t.Fatalf("Unlock = %q, %v", id, err)
	}
	us := s.Unlocks()
	if len(us) != 1 || us[0].RequestID != id || us[0].Source != "mobile_app" || us[0].AccessPointID != ap.String() || us[0].TenantID != tid.String() {
		t.Fatalf("unlocks = %+v", us)
	}

	// The unlock shows up as the newest door release.
	for d, err := range c.DoorReleases(ctx, tid) {
		if err != nil {
			t.Fatal(err)
		}
		if d.AccessPoint.ID != ap || d.Method != "SWIPE_TO_OPEN" {
			t.Errorf("newest release = %+v", d)
		}
		break
	}

	if _, err := c.Unlock(ctx, tid, NewGlobalID("prod", TypeAccessPoint, 1)); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown access point: %v", err)
	}
	if _, err := c.Unlock(ctx, NewGlobalID("prod", TypeTenant, 1), ap); !errors.Is(err, ErrForbidden) {
		t.Errorf("foreign tenant: %v", err)
	}
	if len(s.Unlocks()) != 1 {
		t.Errorf("unlocks = %d", len(s.Unlocks()))
	}
}

func TestGQLUnlockFixtureRequest(t *testing.T) {
	var got struct {
		AccessPointID string `json:"accessPointId"`
		TenantID      string `json:"tenantId"`
		Source        string `json:"source"`
	}
	var path, auth string
	srv := gqlTestUnlockServer(t, func(r *http.Request) []byte {
		path, auth = r.URL.Path+" "+r.Method, r.Header.Get("Authorization")
		_ = json.UnmarshalRead(r.Body, &got)
		return []byte(`{"requestId":"daa4a761-1dab-4849-a5cf-44fb8a317c3b"}`)
	})
	c, _ := newTestClient(t, srv, nil)
	id, err := c.Unlock(context.Background(), gqlTestGID(t, "prod-tenant-7754340"), gqlTestGID(t, "prod-access_point-12921"))
	if err != nil || id != "daa4a761-1dab-4849-a5cf-44fb8a317c3b" {
		t.Fatalf("Unlock = %q, %v", id, err)
	}
	if path != "/v1/access-point POST" || auth != "Bearer tok" ||
		got.AccessPointID != "prod-access_point-12921" || got.TenantID != "prod-tenant-7754340" || got.Source != "mobile_app" {
		t.Errorf("path=%q auth=%q body=%+v", path, auth, got)
	}
}

func TestGQLUnlockNotSupported(t *testing.T) {
	srv := gqlTestUnlockServer(t, func(*http.Request) []byte { return nil })
	c, _ := newTestClient(t, srv, func(o *Options) { o.Environment.UnlockURL = "" })
	_, err := c.Unlock(context.Background(), gqlTestGID(t, "prod-tenant-1"), gqlTestGID(t, "prod-access_point-1"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("err = %v", err)
	}
}

func TestGQLUnlockNoRetryOn5xx(t *testing.T) {
	n := 0
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		n++
		w.WriteHeader(http.StatusBadGateway)
	})
	c, _ := newTestClient(t, srv, nil)
	_, err := c.Unlock(context.Background(), gqlTestGID(t, "prod-tenant-1"), gqlTestGID(t, "prod-access_point-1"))
	if !errors.Is(err, ErrServer) || n != 1 {
		t.Fatalf("err = %v after %d requests", err, n)
	}
}

func gqlTestUnlockServer(t *testing.T, f func(*http.Request) []byte) *httptest.Server {
	t.Helper()
	return newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(f(r))
	})
}
