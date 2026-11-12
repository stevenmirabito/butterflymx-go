package butterflymx

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func isNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

func TestGQLTenantsFixture(t *testing.T) {
	c, _ := gqlTestOps(t, map[string]func(map[string]any) []byte{"Tenants": gqlTestFixture(t, "Tenants")})
	ts, err := c.Tenants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 1 {
		t.Fatalf("len = %d", len(ts))
	}
	gqlTestCheckTenant(t, ts[0])
}

func gqlTestCheckTenant(t *testing.T, tn Tenant) {
	t.Helper()
	if tn.ID.String() != "prod-tenant-7754340" {
		t.Errorf("ID = %v", tn.ID)
	}
	if tn.PIN.Reveal() != "012345" {
		t.Errorf("PIN = %q, want leading zero kept", tn.PIN.Reveal())
	}
	if tn.LegacyPIN != "" || tn.InactiveAfter != nil || tn.AwayMessage != "" {
		t.Errorf("nulls: %+v", tn)
	}
	if tn.Name != "Resident Example" || !tn.DeliveryPassEnabled || !tn.VirtualKeyEnabled || !tn.PrivacyConsentGiven ||
		tn.VirtualFobEntryEnabled || tn.GeofenceEnabled || tn.MaintenanceRequestsEnabled {
		t.Errorf("flags: %+v", tn)
	}
	if tn.Unit.Label != "4B" || tn.Unit.FloorNumber != "4" || tn.Unit.ID.Type != TypeUnit {
		t.Errorf("unit = %+v", tn.Unit)
	}
	b := tn.Building
	if b.TimeZone != "America/Los_Angeles" || b.Country != "us" || b.Name != "Example Tower" ||
		b.GUID != "prod-core-na-building-78323" || b.VirtualKeysDurationPeriod != 365 || b.Suspended || b.Geofence != nil ||
		b.ContactPhoneNumber != "" || b.AmenityReservationsFeeStrategy != "RECORD_PAYMENTS" {
		t.Errorf("building = %+v", b)
	}
	if !b.HasCapability("VIRTUAL_KEYS_ENABLED") || b.HasCapability("NOPE") || len(b.Capabilities) != 4 {
		t.Errorf("capabilities = %v", b.Capabilities)
	}
	loc, err := b.Location()
	if err != nil || loc.String() != "America/Los_Angeles" {
		t.Errorf("Location = %v, %v", loc, err)
	}
	np := tn.NotificationPreference
	if np.Call != "VIDEO_CALL" || np.DoNotDisturb || len(np.DoorOpen) != 1 || len(np.Message) != 2 || np.Message[1] != "SMS" {
		t.Errorf("notification = %+v", np)
	}
	if !tn.CanCreateGuestPasses() {
		t.Error("CanCreateGuestPasses = false")
	}
	tn.Building.Suspended = true
	if tn.CanCreateGuestPasses() {
		t.Error("CanCreateGuestPasses with suspended building")
	}
}

func TestGQLTenantFixture(t *testing.T) {
	c, seen := gqlTestOps(t, map[string]func(map[string]any) []byte{"Tenant": gqlTestFixture(t, "Tenant")})
	id, _ := ParseGlobalID("prod-tenant-7754340")
	tn, err := c.Tenant(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	gqlTestCheckTenant(t, *tn)
	if got := (*seen)[0]["tenantId"]; got != "prod-tenant-7754340" {
		t.Errorf("tenantId var = %v", got)
	}
}

func TestGQLTenantNullAndWrongType(t *testing.T) {
	c, seen := gqlTestOps(t, map[string]func(map[string]any) []byte{
		"Tenant": func(map[string]any) []byte { return []byte(`{"data":{"nodes":[null]}}`) },
	})
	id, _ := ParseGlobalID("prod-tenant-1")
	_, err := c.Tenant(context.Background(), id)
	var e *Error
	if !isNotFound(err) || !errors.As(err, &e) || e.Op != "Tenant" {
		t.Fatalf("err = %v", err)
	}
	ap, _ := ParseGlobalID("prod-access_point-1")
	if _, err := c.Tenant(context.Background(), ap); !errors.Is(err, ErrIDType) {
		t.Fatalf("err = %v, want ErrIDType", err)
	}
	if len(*seen) != 1 {
		t.Errorf("wrong-type call sent a request (%d requests)", len(*seen))
	}
}

func TestGQLTenantsPagination(t *testing.T) {
	page := func(vars map[string]any) []byte {
		node := func(n int) string {
			return fmt.Sprintf(`{"id":"prod-tenant-%d","pinCode":"00000%d","building":{"id":"prod-building-1"}}`, n, n)
		}
		if vars["after"] == nil {
			return []byte(`{"data":{"tenants":{"pageInfo":{"hasNextPage":true,"endCursor":"MQ"},"nodes":[` + node(1) + `]}}}`)
		}
		if vars["after"] != "MQ" {
			t.Errorf("after = %v", vars["after"])
		}
		return []byte(`{"data":{"tenants":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[` + node(2) + `]}}}`)
	}
	c, _ := gqlTestOps(t, map[string]func(map[string]any) []byte{"Tenants": page})
	ts, err := c.Tenants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 2 || ts[1].ID.Num != 2 || ts[1].PIN.Reveal() != "000002" {
		t.Fatalf("tenants = %+v", ts)
	}
}

func TestGQLPartialDataLenient(t *testing.T) {
	// Unknown fields, nulls and a GraphQL error next to data are tolerated.
	c, _ := gqlTestOps(t, map[string]func(map[string]any) []byte{
		"Tenant": func(map[string]any) []byte {
			return []byte(`{"data":{"nodes":[{"id":"prod-tenant-5","brandNew":1,"unit":null,"building":null,"notificationPreference":null,"inactiveAfter":"2027-01-02T03:04:05Z"}]},"errors":[{"message":"boom"}]}`)
		},
	})
	id, _ := ParseGlobalID("prod-tenant-5")
	tn, err := c.Tenant(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if tn.InactiveAfter == nil || tn.InactiveAfter.Year() != 2027 || tn.CanCreateGuestPasses() {
		t.Errorf("tenant = %+v", tn)
	}
}
