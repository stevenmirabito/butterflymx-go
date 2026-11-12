package butterflymx

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func gqlTestTenantID() GlobalID { return NewGlobalID("prod", TypeTenant, 7754340) }

func TestGQLDoorReleasesFixture(t *testing.T) {
	c, _ := gqlTestOps(t, map[string]func(map[string]any) []byte{"TenantDoorReleases": func(vars map[string]any) []byte {
		return fixtureBody(t, "graphql/TenantDoorReleases.json")
	}})
	var got []DoorRelease
	for d, err := range c.DoorReleases(context.Background(), gqlTestTenantID()) {
		if err != nil {
			// The fixture claims a second page; the replayed cursor is
			// rejected by the pager after the 20 first items.
			if !strings.Contains(err.Error(), "cursor") {
				t.Fatal(err)
			}
			break
		}
		got = append(got, d)
	}
	if len(got) < 20 {
		t.Fatalf("len = %d", len(got))
	}
	d := got[0]
	if d.ID.Type != TypeDoorRelease || d.Type != "VISITOR" || d.Method != "SWIPE_TO_OPEN" || d.LicensePlate != nil {
		t.Errorf("d = %+v", d)
	}
	if !d.LoggedAt.Equal(time.Date(2026, 11, 12, 5, 1, 9, 0, time.UTC)) {
		t.Errorf("LoggedAt = %v", d.LoggedAt)
	}
	if d.AccessPoint.Name != "Front Door" || d.AccessPoint.Kind != "AccessPoint" || d.AccessPoint.ID.Num != 12921 ||
		d.Device.Kind != "CloudBasedAccessController" || d.Device.ID.Type != TypeCloudBasedAccessController {
		t.Errorf("refs = %+v / %+v", d.AccessPoint, d.Device)
	}
	if got[1].Device.Kind != "Intercom" {
		t.Errorf("device kind = %q", got[1].Device.Kind)
	}
	methods := map[string]bool{}
	for _, r := range got {
		methods[r.Method] = true
	}
	if !methods["RFID"] || !methods["MOBILE_CALL"] || !methods["VIRTUAL_KEY_PIN"] {
		t.Errorf("methods = %v", methods)
	}
}

func TestGQLDoorReleasesTwoPages(t *testing.T) {
	node := func(n int, plate bool) string {
		lp := "null"
		if plate {
			lp = `{"id":"prod-license_plate-1","number":"ABC123","issuer":{"id":"x","name":"California","country":"US"}}`
		}
		return fmt.Sprintf(`{"__typename":"DoorRelease","id":"prod-door_relase-%d","loggedAt":"2026-11-12T05:0%d:00Z","type":"VISITOR","method":"RFID","licensePlate":%s,"accessPoint":{"__typename":"AccessPoint","id":"prod-access_point-1","name":"A"},"device":null}`, n, n, lp)
	}
	var afters []any
	c, _ := gqlTestOps(t, map[string]func(map[string]any) []byte{"TenantDoorReleases": func(vars map[string]any) []byte {
		afters = append(afters, vars["after"])
		if vars["after"] == nil {
			return []byte(`{"data":{"nodes":[{"id":"prod-tenant-7754340","doorReleases":{"pageInfo":{"hasNextPage":true,"endCursor":"c1"},"nodes":[` + node(1, true) + `,` + node(2, false) + `]}}]}}`)
		}
		return []byte(`{"data":{"nodes":[{"id":"prod-tenant-7754340","doorReleases":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[` + node(3, false) + `]}}]}}`)
	}})
	var ids []ID
	var plate *LicensePlate
	for d, err := range c.DoorReleases(context.Background(), gqlTestTenantID()) {
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, d.ID.Num)
		if d.LicensePlate != nil {
			plate = d.LicensePlate
		}
	}
	if fmt.Sprint(ids) != "[1 2 3]" || len(afters) != 2 || afters[1] != "c1" {
		t.Errorf("ids = %v, afters = %v", ids, afters)
	}
	if plate == nil || plate.Number != "ABC123" || plate.IssuerName != "California" || plate.IssuerCountry != "US" {
		t.Errorf("plate = %+v", plate)
	}
}

func TestGQLDoorReleasesLazyStop(t *testing.T) {
	n := 0
	c, _ := gqlTestOps(t, map[string]func(map[string]any) []byte{"TenantDoorReleases": func(map[string]any) []byte {
		n++
		return []byte(fmt.Sprintf(`{"data":{"nodes":[{"id":"prod-tenant-7754340","doorReleases":{"pageInfo":{"hasNextPage":true,"endCursor":"c%d"},"nodes":[{"id":"prod-door_relase-%d"}]}}]}}`, n, n))
	}})
	for _, err := range c.DoorReleases(context.Background(), gqlTestTenantID()) {
		if err != nil {
			t.Fatal(err)
		}
		break
	}
	if n != 1 {
		t.Errorf("fetched %d pages, want 1", n)
	}
}

func TestGQLCallsFixture(t *testing.T) {
	c, _ := gqlTestOps(t, map[string]func(map[string]any) []byte{"TenantCalls": func(vars map[string]any) []byte {
		return fixtureBody(t, "graphql/TenantCalls.json")
	}})
	var first *Call
	for cl, err := range c.Calls(context.Background(), gqlTestTenantID()) {
		if err != nil {
			break // fixture replays a next-page cursor
		}
		if first == nil {
			first = &cl
			break
		}
	}
	if first == nil {
		t.Fatal("no calls")
	}
	if first.ID.String() != "prod-call-491476629" || first.GUID != "b8c5424b-0196-4862-b4a4-bef989a26419" ||
		first.NotificationType != "VISITOR" || first.DisplayStatus != "OPENED_DOOR" ||
		first.Device.Kind != "Intercom" || first.Device.Name != "Main Entrance" ||
		!first.LoggedAt.Equal(time.Date(2026, 11, 6, 0, 20, 27, 0, time.UTC)) {
		t.Errorf("call = %+v", first)
	}
}

func TestGQLMessages(t *testing.T) {
	var vars []map[string]any
	c, _ := gqlTestOps(t, map[string]func(map[string]any) []byte{"TenantMessages": func(v map[string]any) []byte {
		vars = append(vars, v)
		return []byte(`{"data":{"nodes":[{"id":"prod-tenant-7754340","messages":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[
			{"__typename":"TextMessage","id":"prod-text_message-1","title":"Hi","body":"Body","createdAt":"2026-11-01T10:00:00Z","logoUrl":"l","imageUrl":null,"origin":"PROPERTY_MANAGER","source":{"__typename":"Device","name":"Lobby"}},
			{"__typename":"OtherMessage"}]}}]}}`)
	}})
	ctx := context.Background()
	var msgs []Message
	for m, err := range c.Messages(ctx, gqlTestTenantID(), &MessageOptions{ImageSize: "medium"}) {
		if err != nil {
			t.Fatal(err)
		}
		msgs = append(msgs, m)
	}
	if len(msgs) != 1 || msgs[0].Title != "Hi" || msgs[0].SourceName != "Lobby" || msgs[0].LogoURL != "l" ||
		msgs[0].ImageURL != "" || msgs[0].Origin != "PROPERTY_MANAGER" || msgs[0].CreatedAt.Year() != 2026 {
		t.Errorf("msgs = %+v", msgs)
	}
	if vars[0]["imageSize"] != "medium" {
		t.Errorf("vars = %v", vars[0])
	}
	for _, err := range c.Messages(ctx, gqlTestTenantID(), nil) {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := vars[1]["imageSize"]; ok {
		t.Errorf("imageSize sent without options: %v", vars[1])
	}
}

func TestGQLMessagesFixtureEmpty(t *testing.T) {
	c, _ := gqlTestOps(t, map[string]func(map[string]any) []byte{"TenantMessages": gqlTestFixture(t, "TenantMessages")})
	n := 0
	for _, err := range c.Messages(context.Background(), gqlTestTenantID(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != 0 {
		t.Errorf("n = %d", n)
	}
}

func TestGQLHistoryErrors(t *testing.T) {
	c, seen := gqlTestOps(t, map[string]func(map[string]any) []byte{
		"TenantCalls": func(map[string]any) []byte { return []byte(`{"data":{"nodes":[null]}}`) },
	})
	ctx := context.Background()
	bad := NewGlobalID("prod", TypeAccessPoint, 1)
	check := func(name string, err error, want error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Errorf("%s: err = %v, want %v", name, err, want)
		}
	}
	for _, err := range c.DoorReleases(ctx, bad) {
		check("DoorReleases", err, ErrIDType)
	}
	for _, err := range c.Calls(ctx, bad) {
		check("Calls", err, ErrIDType)
	}
	for _, err := range c.Messages(ctx, bad, nil) {
		check("Messages", err, ErrIDType)
	}
	if len(*seen) != 0 {
		t.Errorf("requests = %d", len(*seen))
	}
	for _, err := range c.Calls(ctx, gqlTestTenantID()) {
		check("Calls unknown", err, ErrNotFound)
	}
}
