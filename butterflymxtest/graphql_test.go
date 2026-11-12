package butterflymxtest

import (
	"testing"
)

func nodes0(t *testing.T, r reply) map[string]any {
	t.Helper()
	return dig(t, r.JSON(t), "data", "nodes", 0).(map[string]any)
}

func TestGraphQLCurrentUser(t *testing.T) {
	s := newTestServer(t)
	tok := apiSession(t, s)
	r := gql(t, s, tok, "CurrentUser", nil)
	wantStatus(t, r, 200)
	u := dig(t, r.JSON(t), "data", "currentUser").(map[string]any)
	if u["email"] != DefaultEmail || u["id"] != s.Seed().UserGlobalID || u["lastName"] != "Example" {
		t.Errorf("user = %v", u)
	}
	if got := dig(t, u, "twoFactorAuthenticationConfig", "enabled"); got != true {
		t.Errorf("2fa enabled = %v", got)
	}
}

func TestGraphQLTenantsAndTenant(t *testing.T) {
	s := newTestServer(t)
	tok := apiSession(t, s)
	sd := s.Seed()
	r := gql(t, s, tok, "Tenants", map[string]any{})
	wantStatus(t, r, 200)
	n := dig(t, r.JSON(t), "data", "tenants", "nodes", 0).(map[string]any)
	if n["id"] != sd.TenantGlobalID || dig(t, n, "building", "timeZone") != "America/Los_Angeles" ||
		dig(t, n, "unit", "label") != "4B" || n["virtualKeyEnabled"] != true {
		t.Errorf("tenant = %v", n)
	}
	pi := dig(t, r.JSON(t), "data", "tenants", "pageInfo").(map[string]any)
	if pi["hasNextPage"] != false || pi["endCursor"] != "MQ" {
		t.Errorf("pageInfo = %v", pi)
	}
	// after the last cursor there is nothing
	r = gql(t, s, tok, "Tenants", map[string]any{"after": "MQ"})
	if got := dig(t, r.JSON(t), "data", "tenants", "nodes").([]any); len(got) != 0 {
		t.Errorf("nodes after MQ = %v", got)
	}

	r = gql(t, s, tok, "Tenant", map[string]any{"tenantId": sd.TenantGlobalID})
	if got := nodes0(t, r); got["id"] != sd.TenantGlobalID || dig(t, got, "building", "virtualKeysDurationPeriod") != float64(365) {
		t.Errorf("Tenant node = %v", got)
	}
	r = gql(t, s, tok, "Tenant", map[string]any{"tenantId": "prod-tenant-1"})
	if got := dig(t, r.JSON(t), "data", "nodes", 0); got != nil {
		t.Errorf("unknown tenant node = %v, want null", got)
	}
}

func TestGraphQLAccessPoints(t *testing.T) {
	s := newTestServer(t, WithPageSize(3))
	tok := apiSession(t, s)
	sd := s.Seed()
	var names []string
	after := ""
	pages := 0
	for {
		r := gql(t, s, tok, "TenantAccessPoints", map[string]any{"ids": []string{sd.TenantGlobalID}, "after": after})
		wantStatus(t, r, 200)
		conn := dig(t, nodes0(t, r), "accessPoints").(map[string]any)
		for _, n := range conn["nodes"].([]any) {
			ap := n.(map[string]any)
			names = append(names, ap["name"].(string))
			if ap["legacyId"] == "" || ap["id"] != "prod-access_point-"+ap["legacyId"].(string) {
				t.Errorf("ids = %v / %v", ap["id"], ap["legacyId"])
			}
		}
		pages++
		pi := conn["pageInfo"].(map[string]any)
		if pi["hasNextPage"] != true {
			break
		}
		after = pi["endCursor"].(string)
		if pages > 10 {
			t.Fatal("pagination does not terminate")
		}
	}
	if pages != 3 || len(names) != 7 {
		t.Errorf("pages=%d names=%v", pages, names)
	}
	// capability and device shapes
	r := gql(t, s, tok, "TenantAccessPoints", map[string]any{"ids": []string{sd.TenantGlobalID}, "after": ""})
	for _, n := range dig(t, nodes0(t, r), "accessPoints", "nodes").([]any) {
		ap := n.(map[string]any)
		caps := ap["capabilities"].([]any)
		hasVK := false
		for _, c := range caps {
			hasVK = hasVK || c == "VIRTUAL_KEYS"
		}
		if hasVK == (ap["name"] == "Roof Terrace") {
			t.Errorf("%v: VIRTUAL_KEYS capability = %v", ap["name"], hasVK)
		}
		dev := dig(t, ap, "devices", "nodes", 0).(map[string]any)
		if ap["name"] == "Main Entrance" && (dev["__typename"] != "Intercom" || dev["serialNumber"] == nil) {
			t.Errorf("panel device = %v", dev)
		}
	}
}

func TestGraphQLDoorReleasesPaginateNewestFirst(t *testing.T) {
	s := newTestServer(t)
	tok := apiSession(t, s)
	sd := s.Seed()
	vars := func(after string) map[string]any {
		return map[string]any{"tenantIds": []string{sd.TenantGlobalID}, "after": after}
	}
	r := gql(t, s, tok, "TenantDoorReleases", vars(""))
	conn := dig(t, nodes0(t, r), "doorReleases").(map[string]any)
	first := conn["nodes"].([]any)
	pi := conn["pageInfo"].(map[string]any)
	if len(first) != 20 || pi["hasNextPage"] != true {
		t.Fatalf("page 1: %d nodes, pageInfo %v", len(first), pi)
	}
	prev := ""
	for _, n := range first {
		at := n.(map[string]any)["loggedAt"].(string)
		if prev != "" && at > prev {
			t.Errorf("not newest first: %s after %s", at, prev)
		}
		prev = at
	}
	all := first
	for pages := 0; pi["hasNextPage"] == true; pages++ {
		if pages > 10 {
			t.Fatal("pagination does not terminate")
		}
		r = gql(t, s, tok, "TenantDoorReleases", vars(pi["endCursor"].(string)))
		next := dig(t, nodes0(t, r), "doorReleases").(map[string]any)
		all = append(all, next["nodes"].([]any)...)
		pi = next["pageInfo"].(map[string]any)
	}
	seen := map[string]bool{}
	for _, n := range all {
		id := n.(map[string]any)["id"].(string)
		if seen[id] {
			t.Errorf("duplicate door release %s", id)
		}
		seen[id] = true
	}
	if len(all) <= 20 {
		t.Errorf("expected more than one page, got %d", len(all))
	}
	// A bad cursor is a GraphQL error.
	r = gql(t, s, tok, "TenantDoorReleases", vars("bm90IGEgY3Vyc29y"))
	if body := r.JSON(t); body["errors"] == nil {
		t.Errorf("expected an error for a bad cursor: %s", r.Body)
	}
}

func TestGraphQLCallsMessagesAndMisc(t *testing.T) {
	s := newTestServer(t)
	tok := apiSession(t, s)
	sd := s.Seed()
	ids := map[string]any{"tenantIds": []string{sd.TenantGlobalID}, "after": ""}

	r := gql(t, s, tok, "TenantCalls", ids)
	calls := dig(t, nodes0(t, r), "calls").(map[string]any)
	if len(calls["nodes"].([]any)) != 20 || dig(t, calls, "pageInfo", "endCursor") != "MjA" || dig(t, calls, "pageInfo", "hasNextPage") != true {
		t.Errorf("calls = %v", calls["pageInfo"])
	}
	ids["after"] = "MjA"
	r = gql(t, s, tok, "TenantCalls", ids)
	if got := dig(t, nodes0(t, r), "calls", "nodes").([]any); len(got) != 5 {
		t.Errorf("calls page 2 = %d", len(got))
	}

	ids = map[string]any{"tenantIds": []string{sd.TenantGlobalID}, "after": "", "imageSize": "medium"}
	r = gql(t, s, tok, "TenantMessages", ids)
	msgs := dig(t, nodes0(t, r), "messages", "nodes").([]any)
	if len(msgs) != 2 || msgs[0].(map[string]any)["__typename"] != "TextMessage" {
		t.Errorf("messages = %v", msgs)
	}

	one := map[string]any{"ids": []string{sd.TenantGlobalID}}
	if n := nodes0(t, gql(t, s, tok, "TenantLPRSettings", one)); n["vehicleVisitorPassesEnabled"] != false {
		t.Errorf("LPR = %v", n)
	}
	if n := nodes0(t, gql(t, s, tok, "TenantRemoteLocks", one)); dig(t, n, "remoteLocks", "pageInfo", "endCursor") != nil {
		t.Errorf("remote locks = %v", n)
	}
	one["excludeAccessPointLocks"] = true
	if n := nodes0(t, gql(t, s, tok, "TenantSmartLocks", one)); len(dig(t, n, "smartLocks", "nodes").([]any)) != 0 {
		t.Errorf("smart locks = %v", n)
	}
	r = gql(t, s, tok, "GetBLECredentials", map[string]any{"tenantId": sd.TenantGlobalID, "userDeviceId": "prod-user_device_apple-1"})
	if dig(t, nodes0(t, r), "building", "wavelynxReaderBleCredential", "kmd") == nil {
		t.Errorf("BLE = %s", r.Body)
	}
}

func TestGraphQLErrorsAndAuth(t *testing.T) {
	s := newTestServer(t)
	tok := apiSession(t, s)

	r := gql(t, s, tok, "NoSuchOperation", nil)
	wantStatus(t, r, 200)
	body := r.JSON(t)
	if v, ok := body["data"]; !ok || v != nil || len(body["errors"].([]any)) != 1 {
		t.Errorf("unknown operation body = %s", r.Body)
	}
	// operation name taken from the document when operationName is missing
	rr := do(t, newClient(), "POST", s.URL()+"/denizen/v1/graphql", []byte(`{"query":"query CurrentUser { currentUser { id } }"}`),
		map[string]string{"Authorization": "Bearer " + tok})
	if dig(t, rr.JSON(t), "data", "currentUser", "id") == nil {
		t.Errorf("body = %s", rr.Body)
	}

	wantStatus(t, gql(t, s, "", "CurrentUser", nil), 401)
	wantStatus(t, gql(t, s, "nonsense", "CurrentUser", nil), 401)
	// the OAuth token is not accepted on the API
	wantStatus(t, gql(t, s, login(t, s).Access, "CurrentUser", nil), 401)
}
