package butterflymxtest

import (
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixedServer(t *testing.T, opts ...Option) (*Server, string) {
	t.Helper()
	opts = append([]Option{WithClock(func() time.Time { return fixedNow })}, opts...)
	s := newTestServer(t, opts...)
	return s, apiSession(t, s)
}

// postFixture sends a fixture's request body to the fake.
func postFixture(t *testing.T, s *Server, tok, rel string, ids map[string]string) reply {
	t.Helper()
	f := loadFixture(t, rel)
	path := f.Request.Path
	body := f.reqJSON()
	if ids != nil {
		path, body = replaceIDs(path, ids), replaceIDs(body, ids)
	}
	return api(t, s, tok, f.Request.Method, path, body)
}

func attrs(t *testing.T, v any) map[string]any {
	t.Helper()
	return dig(t, v, "attributes").(map[string]any)
}

func included(t *testing.T, doc map[string]any, typ string) []map[string]any {
	t.Helper()
	var out []map[string]any
	inc, _ := doc["included"].([]any)
	for _, x := range inc {
		m := x.(map[string]any)
		if m["type"] == typ {
			out = append(out, m)
		}
	}
	return out
}

func TestCreateCustomPassDerivesLocalFields(t *testing.T) {
	s, tok := fixedServer(t)
	r := postFixture(t, s, tok, "rest/post-keychains-custom-201", nil)
	wantStatus(t, r, 201)
	if ct := r.Header.Get("Content-Type"); ct != "application/vnd.api+json; charset=utf-8" || r.Header.Get("ETag") == "" {
		t.Errorf("headers = %v", r.Header)
	}
	doc := r.JSON(t)
	a := attrs(t, doc["data"])
	want := map[string]any{
		"name": "Test", "kind": "custom", "starts_at": "2026-11-12T05:00:00Z", "ends_at": "2026-11-12T06:00:00Z",
		"start_date": "2026-11-11", "end_date": "2026-11-11", "time_from": "21:00", "time_to": "22:00",
		"allow_unit_access": false,
	}
	for k, v := range want {
		if a[k] != v {
			t.Errorf("%s = %v, want %v", k, a[k], v)
		}
	}
	if w, _ := a["weekdays"].([]any); w == nil || len(w) != 0 {
		t.Errorf("weekdays = %v", a["weekdays"])
	}
	vks := included(t, doc, "virtual_keys")
	if len(vks) != 1 {
		t.Fatalf("virtual keys = %d", len(vks))
	}
	va := attrs(t, vks[0])
	if va["email"] != "resident@example.com" || va["sms_number"] != nil || va["sent_at"] != nil || va["name"] != "Resident Example" {
		t.Errorf("vk attrs = %v", va)
	}
	if !regexp.MustCompile(`^\d{6}$`).MatchString(va["pin"].(string)) {
		t.Errorf("pin = %v", va["pin"])
	}
	id := vks[0]["id"].(string)
	if !regexp.MustCompile(`^https://s3\.dualstack\.us-east-1\.amazonaws\.com/bmx-rails-production/system/qr_keys/qr_code_images/\d{3}/\d{3}/\d{3}/original/qr_code_20261112-1-[a-z0-9]{6}\.png$`).MatchString(va["qr_code_image_url"].(string)) ||
		!regexp.MustCompile(`^https://user\.butterflymx\.com/public/virtual_keys/`+id+`/[0-9a-f]{32}$`).MatchString(va["instructions_url"].(string)) {
		t.Errorf("urls = %v / %v", va["qr_code_image_url"], va["instructions_url"])
	}
	// derived devices: 3 controllers + 1 panel for the 6 doors
	devs := dig(t, doc, "data", "relationships", "devices", "data").([]any)
	if len(devs) != 4 || len(included(t, doc, "panels")) != 1 || len(included(t, doc, "cloud_keyz_controllers")) != 3 {
		t.Errorf("devices = %v", devs)
	}

	// one email recorded, sent_at is set on the next read
	ds := s.SentDeliveries()
	if len(ds) != 1 || ds[0].Channel != "email" || ds[0].To != "resident@example.com" || ds[0].PIN != va["pin"] || !ds[0].SentAt.IsZero() {
		t.Fatalf("deliveries = %+v", ds)
	}
	kid := dig(t, doc, "data", "id").(string)
	g := api(t, s, tok, "GET", "/v3/keychains/"+kid+"?include=virtual_keys", nil)
	wantStatus(t, g, 200)
	if got := attrs(t, included(t, g.JSON(t), "virtual_keys")[0])["sent_at"]; got != "2026-11-12T05:12:03Z" {
		t.Errorf("sent_at on read = %v", got)
	}
	if ds := s.SentDeliveries(); ds[0].SentAt.IsZero() {
		t.Error("delivery not marked as sent")
	}
	if kcs := s.Keychains(); kcs[len(kcs)-1].ID != kid || len(kcs[len(kcs)-1].VirtualKeys) != 1 {
		t.Errorf("Keychains() = %+v", kcs[len(kcs)-1])
	}
}

func TestCreateRecurringPassDerivesInstants(t *testing.T) {
	s, tok := fixedServer(t)
	r := postFixture(t, s, tok, "rest/post-keychains-recurring-201", nil)
	wantStatus(t, r, 201)
	a := attrs(t, r.JSON(t)["data"])
	want := map[string]any{
		"name": "Test Recurring", "kind": "recurring", "starts_at": "2026-11-11T17:00:00Z", "ends_at": "2026-12-01T01:00:00Z",
		"start_date": "2026-11-11", "end_date": "2026-11-30", "time_from": "09:00", "time_to": "17:00",
	}
	for k, v := range want {
		if a[k] != v {
			t.Errorf("%s = %v, want %v", k, a[k], v)
		}
	}
	if fmt.Sprint(a["weekdays"]) != "[mon wed fri]" {
		t.Errorf("weekdays = %v", a["weekdays"])
	}
}

func TestDerivationAcrossDST(t *testing.T) {
	s, tok := fixedServer(t)
	body := func(sd, ed, tf, tt string) string {
		return fmt.Sprintf(`{"data":{"type":"keychains","attributes":{"name":"dst","weekdays":["sat"],"time_from":%q,"time_to":%q,"start_date":%q,"end_date":%q,"recipients":[{"name":"G","deliver_to":"g@example.com"}]},
		"relationships":{"tenant":{"data":{"type":"tenants","id":"7754340"}},"access_points":{"data":[{"type":"access_points","id":"28821"}]}}}}`, tf, tt, sd, ed)
	}
	// PDT (UTC-7) on 2026-10-30, PST (UTC-8) on 2026-11-02.
	r := api(t, s, tok, "POST", "/v3/keychains/recurring", body("2026-10-30", "2026-11-02", "09:00", "17:00"))
	wantStatus(t, r, 201)
	a := attrs(t, r.JSON(t)["data"])
	if a["starts_at"] != "2026-10-30T16:00:00Z" || a["ends_at"] != "2026-11-03T01:00:00Z" {
		t.Errorf("recurring across DST: %v / %v", a["starts_at"], a["ends_at"])
	}
	// custom: 2027-07-01T07:00Z is midnight in PDT.
	cu := (`{"data":{"type":"keychains","attributes":{"name":"c","starts_at":"2027-07-01T07:00:00Z","ends_at":"2027-07-01T08:30:00-0700"},
		"relationships":{"tenant":{"data":{"type":"tenants","id":"7754340"}},"access_points":{"data":[{"type":"access_points","id":"28821"}]}}}}`)
	r = api(t, s, tok, "POST", "/v3/keychains/custom", cu)
	wantStatus(t, r, 201)
	a = attrs(t, r.JSON(t)["data"])
	if a["time_from"] != "00:00" || a["start_date"] != "2027-07-01" || a["ends_at"] != "2027-07-01T15:30:00Z" || a["time_to"] != "08:30" {
		t.Errorf("custom derivation = %v", a)
	}
}

func TestRecipientsClassifiedAndNormalized(t *testing.T) {
	for in, want := range map[string]string{
		"alex@example.com":  "email:alex@example.com",
		"(315) 555-0123":    "sms:+13155550123",
		"315-555-0123":      "sms:+13155550123",
		"1 315 555 0123":    "sms:+13155550123",
		"+13155550123":      "sms:+13155550123",
		"+44 20 7946 0958":  "sms:+442079460958",
		"+1 (555) 555-0100": "sms:+15555550100",
	} {
		ch, to, err := classifyDeliverTo(in)
		if err != nil || ch+":"+to != want {
			t.Errorf("classify(%q) = %s:%s %v, want %s", in, ch, to, err, want)
		}
	}
	for _, in := range []string{"", "nope", "12345", "a@b", "x y@example.com", "555-CALL-NOW"} {
		if _, _, err := classifyDeliverTo(in); err == nil {
			t.Errorf("classify(%q) succeeded", in)
		}
	}
}

func TestPINsAreSixDigitsWithLeadingZeros(t *testing.T) {
	s := newTestServer(t)
	zero := 0
	seen := map[string]bool{}
	for i := 0; i < 300; i++ {
		p := s.newPIN()
		if len(p) != 6 || seen[p] {
			t.Fatalf("bad or duplicate pin %q", p)
		}
		seen[p] = true
		s.w.keychains[0].vks[0].pin = p // make newPIN avoid it in the next round (cheap uniqueness)
		if p[0] == '0' {
			zero++
		}
	}
	if zero == 0 {
		t.Error("never generated a PIN with a leading zero")
	}
}

func TestAddAndRevokeVirtualKeys(t *testing.T) {
	s, tok := fixedServer(t)
	c := postFixture(t, s, tok, "rest/post-keychains-custom-201", nil)
	kid := dig(t, c.JSON(t), "data", "id").(string)
	ids := map[string]string{"85303961": kid}

	r := postFixture(t, s, tok, "rest/post-keychains-virtual-keys-201", ids)
	wantStatus(t, r, 201)
	data := r.JSON(t)["data"].([]any)
	if len(data) != 1 {
		t.Fatalf("data = %v", data)
	}
	va := attrs(t, data[0])
	if va["sms_number"] != "+15555550100" || va["email"] != nil || va["sent_at"] != nil {
		t.Errorf("vk attrs = %v", va)
	}
	vkID := dig(t, data[0], "id").(string)
	if d := s.SentDeliveries(); len(d) != 2 || d[1].Channel != "sms" || d[1].To != "+15555550100" {
		t.Errorf("deliveries = %+v", d)
	}

	g := api(t, s, tok, "GET", "/v3/keychains/"+kid+"?include=virtual_keys", nil).JSON(t)
	if ks := included(t, g, "virtual_keys"); len(ks) != 2 || attrs(t, ks[1])["sent_at"] == nil {
		t.Errorf("keys after add = %v", ks)
	}

	// revoke it
	ids["12915969"] = vkID
	r = postFixture(t, s, tok, "rest/delete-keychains-virtual-keys-204", ids)
	wantStatus(t, r, 204)
	if len(r.Body) != 0 {
		t.Errorf("204 body = %q", r.Body)
	}
	g = api(t, s, tok, "GET", "/v3/keychains/"+kid+"?include=virtual_keys", nil).JSON(t)
	if ks := included(t, g, "virtual_keys"); len(ks) != 1 {
		t.Errorf("keys after revoke = %d", len(ks))
	}
	wantStatus(t, api(t, s, tok, "DELETE", "/v3/keychains/"+kid+"/virtual_keys/"+vkID, nil), 404)

	// validation
	bad := `{"data":{"type":"virtual_keys","attributes":{"recipients":[{"name":"X","deliver_to":"???"}]}}}`
	wantStatus(t, api(t, s, tok, "POST", "/v3/keychains/"+kid+"/virtual_keys", bad), 400)
	wantStatus(t, api(t, s, tok, "POST", "/v3/keychains/"+kid+"/virtual_keys", `{"data":{"type":"virtual_keys","attributes":{"recipients":[]}}}`), 400)
	wantStatus(t, api(t, s, tok, "POST", "/v3/keychains/999/virtual_keys", bad), 404)

	// delete the whole keychain
	r = postFixture(t, s, tok, "rest/delete-keychains-204", ids2(kid))
	wantStatus(t, r, 204)
	wantStatus(t, api(t, s, tok, "GET", "/v3/keychains/"+kid, nil), 404)
	wantStatus(t, api(t, s, tok, "DELETE", "/v3/keychains/"+kid, nil), 404)
}

func ids2(kid string) map[string]string { return map[string]string{"85303961": kid} }

func TestDeliveryPassLifecycle(t *testing.T) {
	s, tok := fixedServer(t)
	r := postFixture(t, s, tok, "rest/post-keychains-delivery-pass-201", nil)
	wantStatus(t, r, 201)
	doc := r.JSON(t)
	a := attrs(t, doc["data"])
	want := map[string]any{
		"name": "Delivery Pass", "kind": "delivery_pass", "starts_at": "2026-11-12T05:12:03Z", "ends_at": "2026-12-12T05:12:03Z",
		"start_date": "2026-11-11", "end_date": "2026-12-11", "time_from": "21:12", "time_to": "21:12",
	}
	for k, v := range want {
		if a[k] != v {
			t.Errorf("%s = %v, want %v", k, a[k], v)
		}
	}
	vks := included(t, doc, "virtual_keys")
	if len(vks) != 1 || len(doc["included"].([]any)) != 1 {
		t.Fatalf("included = %v", doc["included"])
	}
	va := attrs(t, vks[0])
	if va["name"] != "Delivery Pass" || va["email"] != nil || va["sms_number"] != nil {
		t.Errorf("vk = %v", va)
	}
	if len(dig(t, doc, "data", "relationships", "devices", "data").([]any)) != 4 {
		t.Errorf("devices = %v", doc["data"])
	}
	if len(s.SentDeliveries()) != 0 {
		t.Error("a delivery pass must not send anything")
	}
	kid := dig(t, doc, "data", "id").(string)
	vkID := vks[0]["id"].(string)
	ids := map[string]string{"75337466": kid, "55244830": vkID}

	// rename: keychain and key
	wantStatus(t, postFixture(t, s, tok, "rest/patch-keychains-delivery-pass-204-rename", ids), 204)
	g := api(t, s, tok, "GET", "/v3/keychains/"+kid+"?include=virtual_keys", nil).JSON(t)
	if attrs(t, g["data"])["name"] != "Test Delivery" || attrs(t, included(t, g, "virtual_keys")[0])["name"] != "Test Delivery" {
		t.Errorf("after rename = %v", g)
	}

	// extend: ends_at wins over the stale end_date in the same body
	wantStatus(t, postFixture(t, s, tok, "rest/patch-keychains-delivery-pass-204-extend", ids), 204)
	g = api(t, s, tok, "GET", "/v3/keychains/"+kid, nil).JSON(t)
	a = attrs(t, g["data"])
	if a["ends_at"] != "2027-01-11T05:12:03Z" || a["end_date"] != "2027-01-10" || a["time_to"] != "21:12" {
		t.Errorf("after extend = %v", a)
	}

	// a partial body is accepted too (unverified in reality)
	wantStatus(t, api(t, s, tok, "PATCH", "/v3/keychains/delivery_pass/"+kid, `{"data":{"type":"keychains","attributes":{"name":"Amazon"}}}`), 204)
	if got := s.Keychains(); got[len(got)-1].Name != "Amazon" {
		t.Errorf("name = %v", got[len(got)-1].Name)
	}
	// ends_at before starts_at is invalid
	wantStatus(t, api(t, s, tok, "PATCH", "/v3/keychains/delivery_pass/"+kid, `{"data":{"type":"keychains","attributes":{"ends_at":"2026-01-01T00:00:00Z"}}}`), 400)
	// not a delivery pass: 404 on this endpoint
	wantStatus(t, api(t, s, tok, "PATCH", "/v3/keychains/delivery_pass/"+s.Seed().ActiveKeychainIDs[0], `{"data":{"type":"keychains","attributes":{"name":"x"}}}`), 404)

	wantStatus(t, postFixture(t, s, tok, "rest/delete-keychains-delivery-pass-204", ids), 204)
	wantStatus(t, api(t, s, tok, "GET", "/v3/keychains/"+kid, nil), 404)
}

func TestDeliveryPassIgnoresAccessPoints(t *testing.T) {
	s, tok := fixedServer(t)
	rel := func(aps string) string {
		return `{"data":{"type":"keychains","attributes":{"name":"Doors"},"relationships":{"tenant":{"data":{"type":"tenants","id":"7754340"}},"access_points":{"data":[` + aps + `]}}}}`
	}
	n := func(aps string) int {
		r := api(t, s, tok, "POST", "/v3/keychains/delivery_pass", rel(aps))
		wantStatus(t, r, 201)
		return len(dig(t, r.JSON(t), "data", "relationships", "devices", "data").([]any))
	}
	all := n("")
	if all < 2 {
		t.Fatalf("devices = %d", all)
	}
	if got := n(`{"type":"access_points","id":"28821"}`); got != all {
		t.Errorf("one door listed: devices = %d, want %d", got, all)
	}
	// Even a door without VIRTUAL_KEYS is ignored.
	if got := n(`{"type":"access_points","id":"44001"}`); got != all {
		t.Errorf("bad door listed: devices = %d, want %d", got, all)
	}
}

func TestListFiltersAndPagination(t *testing.T) {
	s, tok := fixedServer(t)
	sd := s.Seed()
	base := "/v3/access_codes?filter[tenant]=" + sd.TenantID + "&include=" + strings.ReplaceAll(url.QueryEscape("devices,virtual_keys,virtual_keys.door_releases,virtual_keys.door_releases.panel"), "%", "%%") + "&page[size]=20&page[number]=%d&filter[status]=%s"

	r := api(t, s, tok, "GET", fmt.Sprintf(base, 1, "active"), nil)
	wantStatus(t, r, 200)
	doc := r.JSON(t)
	data := doc["data"].([]any)
	if len(data) != 6 {
		t.Fatalf("active = %d", len(data))
	}
	var prevEnd string
	for _, d := range data {
		end := attrs(t, d)["ends_at"].(string)
		if prevEnd != "" && end > prevEnd {
			t.Errorf("active list not newest end first")
		}
		prevEnd = end
	}
	links := doc["links"].(map[string]any)
	if links["next"] != nil || links["prev"] != nil || !strings.HasPrefix(links["self"].(string), s.URL()+"/v3/access_codes?filter%5Bstatus%5D=active&filter%5Btenant%5D=7754340&include=devices%2Cvirtual_keys") {
		t.Errorf("links = %v", links)
	}
	for _, typ := range []string{"virtual_keys", "door_releases", "panels", "cloud_keyz_controllers"} {
		if len(included(t, doc, typ)) == 0 {
			t.Errorf("no included %s", typ)
		}
	}

	// expired: 24 passes -> two pages
	r1 := api(t, s, tok, "GET", fmt.Sprintf(base, 1, "expired"), nil).JSON(t)
	r2 := api(t, s, tok, "GET", fmt.Sprintf(base, 2, "expired"), nil).JSON(t)
	l1, l2 := r1["links"].(map[string]any), r2["links"].(map[string]any)
	if len(r1["data"].([]any)) != 20 || len(r2["data"].([]any)) != 4 {
		t.Fatalf("expired pages: %d + %d", len(r1["data"].([]any)), len(r2["data"].([]any)))
	}
	if l1["next"] == nil || l1["prev"] != nil || l2["next"] != nil || l2["prev"] == nil || l1["last"] != l2["last"] ||
		!strings.Contains(l1["next"].(string), "page%5Bnumber%5D=2") || !strings.Contains(l2["self"].(string), "page%5Bnumber%5D=2") {
		t.Errorf("links: %v / %v", l1, l2)
	}
	// no overlap between active and expired, newest first within expired
	seen := map[string]bool{}
	for _, d := range data {
		seen[dig(t, d, "id").(string)] = true
	}
	last := ""
	for _, page := range []map[string]any{r1, r2} {
		for _, d := range page["data"].([]any) {
			id := dig(t, d, "id").(string)
			if seen[id] {
				t.Errorf("pass %s listed twice", id)
			}
			seen[id] = true
			end := attrs(t, d)["ends_at"].(string)
			if last != "" && end > last {
				t.Errorf("expired not newest first")
			}
			last = end
		}
	}

	// without include there is no "included"; without status both lists
	plain := api(t, s, tok, "GET", "/v3/access_codes?filter[tenant]="+sd.TenantID+"&page[size]=100", nil).JSON(t)
	if _, has := plain["included"]; has || len(plain["data"].([]any)) != 30 {
		t.Errorf("plain list: %d items, included=%v", len(plain["data"].([]any)), has)
	}
	// custom page size from the option applies when the request has none
	s2, tok2 := fixedServer(t, WithPageSize(4))
	if n := len(api(t, s2, tok2, "GET", "/v3/access_codes?filter[status]=expired", nil).JSON(t)["data"].([]any)); n != 4 {
		t.Errorf("WithPageSize: %d", n)
	}

	// errors
	wantStatus(t, api(t, s, tok, "GET", "/v3/access_codes?filter[tenant]=1", nil), 403)
	// unknown status values are ignored, so every pass comes back
	all := api(t, s, tok, "GET", "/v3/access_codes?filter[status]=upcoming&page[size]=100", nil)
	wantStatus(t, all, 200)
	nAll := len(all.JSON(t)["data"].([]any))
	nAct := len(api(t, s, tok, "GET", "/v3/access_codes?filter[status]=active&page[size]=100", nil).JSON(t)["data"].([]any))
	nExp := len(api(t, s, tok, "GET", "/v3/access_codes?filter[status]=expired&page[size]=100", nil).JSON(t)["data"].([]any))
	if nAll != nAct+nExp {
		t.Errorf("unknown status: %d passes, want active %d + expired %d", nAll, nAct, nExp)
	}
	wantStatus(t, api(t, s, tok, "GET", "/v3/access_codes?page[size]=0", nil), 400)
}

func TestListStatusFollowsClockAndUse(t *testing.T) {
	now := fixedNow
	s := newTestServer(t, WithClock(func() time.Time { return now }))
	tok := apiSession(t, s)
	sd := s.Seed()
	count := func(status string) int {
		return len(api(t, s, tok, "GET", "/v3/access_codes?page[size]=100&filter[status]="+status, nil).JSON(t)["data"].([]any))
	}
	if count("active") != 6 || count("expired") != 24 {
		t.Fatalf("initial counts %d/%d", count("active"), count("expired"))
	}
	// a one-time delivery pass key that was used counts as expired
	if err := s.AddDoorRelease("69527006", "28821"); err != nil {
		t.Fatal(err)
	}
	if count("active") != 5 || count("expired") != 25 {
		t.Errorf("after use %d/%d", count("active"), count("expired"))
	}
	g := api(t, s, tok, "GET", "/v3/keychains/"+sd.DeliveryPassID+"?include=virtual_keys.door_releases", nil).JSON(t)
	va := attrs(t, included(t, g, "virtual_keys")[0])
	if va["used_at"] == nil || va["used_at"] != va["one_time_key_used_at"] {
		t.Errorf("used flags = %v", va)
	}
	rel := included(t, g, "door_releases")
	if len(rel) != 1 || attrs(t, rel[0])["release_method"] != "delivery_pass" || attrs(t, rel[0])["door_release_type"] != "delivery" {
		t.Errorf("door releases = %v", rel)
	}
	// time passing expires guest passes
	now = now.Add(400 * 24 * time.Hour)
	if count("active") != 0 {
		t.Errorf("after 400 days active = %d", count("active"))
	}
}

func TestAddDoorReleaseOnGuestKey(t *testing.T) {
	s, tok := fixedServer(t)
	r := postFixture(t, s, tok, "rest/post-keychains-custom-201", nil)
	doc := r.JSON(t)
	kid := dig(t, doc, "data", "id").(string)
	vk := included(t, doc, "virtual_keys")[0]["id"].(string)
	if err := s.AddDoorRelease(vk, "28821"); err != nil {
		t.Fatal(err)
	}
	g := api(t, s, tok, "GET", "/v3/keychains/"+kid+"?include=virtual_keys.door_releases.panel", nil).JSON(t)
	rel := included(t, g, "door_releases")
	if len(rel) != 1 || attrs(t, rel[0])["release_method"] != "virtual_key_pin" || len(included(t, g, "panels")) != 1 {
		t.Errorf("included = %v", g["included"])
	}
	if va := attrs(t, included(t, g, "virtual_keys")[0]); va["used_at"] != nil {
		t.Errorf("guest keys are not one-time keys: %v", va)
	}
	// it also shows up in the GraphQL history, newest first
	gr := gql(t, s, tok, "TenantDoorReleases", map[string]any{"tenantIds": []string{s.Seed().TenantGlobalID}, "after": ""})
	first := dig(t, nodes0(t, gr), "doorReleases", "nodes", 0)
	if dig(t, first, "method") != "VIRTUAL_KEY_PIN" || dig(t, first, "accessPoint", "id") != "prod-access_point-28821" {
		t.Errorf("first release = %v", first)
	}
	// errors
	if s.AddDoorRelease("nope", "28821") == nil || s.AddDoorRelease(vk, "nope") == nil || s.AddDoorRelease(vk, "44001") == nil {
		t.Error("expected errors for unknown key, unknown door and a door outside the pass")
	}
}

func TestETagAndNotModified(t *testing.T) {
	s, tok := fixedServer(t)
	kid := s.Seed().ActiveKeychainIDs[0]
	path := "/v3/keychains/" + kid + "?include=virtual_keys"
	get := func(inm string) reply {
		h := map[string]string{"Authorization": "Bearer " + tok}
		if inm != "" {
			h["If-None-Match"] = inm
		}
		return do(t, newClient(), "GET", s.URL()+path, nil, h)
	}
	r := get("")
	wantStatus(t, r, 200)
	tag := r.Header.Get("ETag")
	if !strings.HasPrefix(tag, `W/"`) {
		t.Fatalf("etag = %q", tag)
	}
	r = get(tag)
	wantStatus(t, r, 304)
	if len(r.Body) != 0 || r.Header.Get("ETag") != tag {
		t.Errorf("304 = %q %v", r.Body, r.Header)
	}
	wantStatus(t, get(`"other", `+tag), 304)
	wantStatus(t, get(`W/"nope"`), 200)

	// a change produces a new ETag
	wantStatus(t, api(t, s, tok, "POST", "/v3/keychains/"+kid+"/virtual_keys", `{"data":{"type":"virtual_keys","attributes":{"recipients":[{"name":"N","deliver_to":"n@example.com"}]}}}`), 201)
	r = get(tag)
	wantStatus(t, r, 200)
	if r.Header.Get("ETag") == tag {
		t.Error("ETag did not change")
	}

	// list revalidation
	lp := "/v3/access_codes?filter[tenant]=7754340&filter[status]=active&page[size]=20&page[number]=1"
	l := api(t, s, tok, "GET", lp, nil)
	l2 := do(t, newClient(), "GET", s.URL()+lp, nil, map[string]string{"Authorization": "Bearer " + tok, "If-None-Match": l.Header.Get("ETag")})
	wantStatus(t, l2, 304)
}

func TestFailNext(t *testing.T) {
	s, tok := fixedServer(t)
	s.FailNext("GET", "/v3/access_codes", 503, 2)
	s.FailNext("POST", "/v3/keychains", 429, 1)
	for i := 0; i < 2; i++ {
		r := api(t, s, tok, "GET", "/v3/access_codes", nil)
		wantStatus(t, r, 503)
		if r.JSON(t)["errors"] == nil {
			t.Errorf("fault body = %s", r.Body)
		}
	}
	wantStatus(t, api(t, s, tok, "GET", "/v3/access_codes", nil), 200)
	// other paths and methods are unaffected until their own fault fires
	wantStatus(t, api(t, s, tok, "GET", "/v3/keychains/"+s.Seed().ActiveKeychainIDs[0], nil), 200)
	r := api(t, s, tok, "POST", "/v3/keychains/delivery_pass", `{}`)
	wantStatus(t, r, 429)
	if r.Header.Get("Retry-After") == "" {
		t.Error("429 without Retry-After")
	}
	if r := api(t, s, tok, "POST", "/v3/keychains/delivery_pass", `{}`); r.StatusCode == http.StatusTooManyRequests {
		t.Error("fault fired more often than requested")
	}
	// faults apply before authentication, to any host's paths
	s.FailNext("", "/denizen/v1/graphql", 502, 1)
	wantStatus(t, gql(t, s, "bad-token", "CurrentUser", nil), 502)
	s.FailNext("POST", "/oauth/token", 500, 1)
	r = postToken(t, s, "grant_type", "refresh_token", "refresh_token", "x", "client_id", ClientID)
	wantStatus(t, r, 500)
	s.FailNext("GET", "/v3/", 401, 1)
	wantStatus(t, api(t, s, tok, "GET", "/v3/access_codes", nil), 401)

	var faulted int
	for _, rq := range s.Requests() {
		if rq.Faulted {
			faulted++
			if rq.Status < 400 {
				t.Errorf("faulted request with status %d", rq.Status)
			}
		}
	}
	if faulted != 6 {
		t.Errorf("faulted requests = %d, want 6", faulted)
	}
}

func TestRequestRecording(t *testing.T) {
	s, tok := fixedServer(t)
	api(t, s, tok, "GET", "/v3/access_codes?filter[tenant]=7754340&page[size]=5", nil)
	reqs := s.Requests()
	last := reqs[len(reqs)-1]
	if last.Method != http.MethodGet || last.Path != "/v3/access_codes" || last.Query.Get("page[size]") != "5" || last.Status != 200 {
		t.Errorf("record = %+v", last)
	}
	if got := last.Header.Get("Authorization"); got != "Bearer [REDACTED]" {
		t.Errorf("Authorization = %q", got)
	}
	api(t, s, tok, "POST", "/denizen/v1/graphql", `{"operationName":"CurrentUser","variables":{"token":"hunter2"}}`)
	reqs = s.Requests()
	if b := reqs[len(reqs)-1].Body; strings.Contains(b, "hunter2") || !strings.Contains(b, "CurrentUser") {
		t.Errorf("body = %s", b)
	}
}

func TestValidationErrors(t *testing.T) {
	s, tok := fixedServer(t)
	body := func(attrs, rels string) string {
		return `{"data":{"type":"keychains","attributes":` + attrs + `,"relationships":` + rels + `}}`
	}
	rels := func(tenant string, aps ...string) string {
		var l []string
		for _, a := range aps {
			l = append(l, `{"type":"access_points","id":"`+a+`"}`)
		}
		return `{"tenant":{"data":{"type":"tenants","id":"` + tenant + `"}},"access_points":{"data":[` + strings.Join(l, ",") + `]}}`
	}
	good := rels("7754340", "28821")
	cases := []struct {
		name, path, body, pointer, detail string
	}{
		{"end before start", "custom", body(`{"name":"x","starts_at":"2026-11-12T06:00:00Z","ends_at":"2026-11-12T05:00:00Z"}`, good), "/data/attributes/ends_at", "after"},
		{"zero length", "custom", body(`{"name":"x","starts_at":"2026-11-12T06:00:00Z","ends_at":"2026-11-12T06:00:00Z"}`, good), "/data/attributes/ends_at", "after"},
		{"too long", "custom", body(`{"name":"x","starts_at":"2026-11-12T06:00:00Z","ends_at":"2027-11-13T06:00:00Z"}`, good), "/data/attributes/ends_at", "365"},
		{"no virtual key capability", "custom", body(`{"name":"x","starts_at":"2026-11-12T05:00:00Z","ends_at":"2026-11-12T06:00:00Z"}`, rels("7754340", "44001")), "/data/relationships/access_points/data/0", "virtual keys"},
		{"unknown access point", "custom", body(`{"name":"x","starts_at":"2026-11-12T05:00:00Z","ends_at":"2026-11-12T06:00:00Z"}`, rels("7754340", "1")), "/data/relationships/access_points/data/0", "not found"},
		{"no access points", "custom", body(`{"name":"x","starts_at":"2026-11-12T05:00:00Z","ends_at":"2026-11-12T06:00:00Z"}`, rels("7754340")), "/data/relationships/access_points", "blank"},
		{"unknown tenant", "custom", body(`{"name":"x","starts_at":"2026-11-12T05:00:00Z","ends_at":"2026-11-12T06:00:00Z"}`, rels("42", "28821")), "/data/relationships/tenant", "tenant"},
		{"bad timestamp", "custom", body(`{"name":"x","starts_at":"tomorrow","ends_at":"2026-11-12T06:00:00Z"}`, good), "/data/attributes/starts_at", "RFC 3339"},
		{"missing name", "custom", body(`{"starts_at":"2026-11-12T05:00:00Z","ends_at":"2026-11-12T06:00:00Z"}`, good), "/data/attributes/name", "blank"},
		{"bad recipient", "custom", body(`{"name":"x","starts_at":"2026-11-12T05:00:00Z","ends_at":"2026-11-12T06:00:00Z","recipients":[{"name":"a","deliver_to":"nope"}]}`, good), "/data/attributes/recipients/0/deliver_to", "email"},
		{"recurring end before start", "recurring", body(`{"name":"x","weekdays":["mon"],"time_from":"09:00","time_to":"17:00","start_date":"2026-11-30","end_date":"2026-11-11"}`, good), "/data/attributes/end_date", "start_date"},
		{"recurring too long", "recurring", body(`{"name":"x","weekdays":["mon"],"time_from":"09:00","time_to":"17:00","start_date":"2026-11-11","end_date":"2028-01-01"}`, good), "/data/attributes/end_date", "365"},
		{"recurring bad weekday", "recurring", body(`{"name":"x","weekdays":["monday"],"time_from":"09:00","time_to":"17:00","start_date":"2026-11-11","end_date":"2026-11-30"}`, good), "/data/attributes/weekdays", "monday"},
		{"recurring no weekdays", "recurring", body(`{"name":"x","weekdays":[],"time_from":"09:00","time_to":"17:00","start_date":"2026-11-11","end_date":"2026-11-30"}`, good), "/data/attributes/weekdays", "blank"},
		{"recurring bad time", "recurring", body(`{"name":"x","weekdays":["mon"],"time_from":"9am","time_to":"17:00","start_date":"2026-11-11","end_date":"2026-11-30"}`, good), "/data/attributes/time_from", "HH:MM"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := api(t, s, tok, "POST", "/v3/keychains/"+tc.path, tc.body)
			wantStatus(t, r, 400)
			if ct := r.Header.Get("Content-Type"); ct != "application/vnd.api+json; charset=utf-8" {
				t.Errorf("content type = %q", ct)
			}
			errs := r.JSON(t)["errors"].([]any)
			var found bool
			for _, e := range errs {
				m := e.(map[string]any)
				// Members carry only source.pointer and detail, like the real server.
				if len(m) > 2 || m["detail"] == nil {
					t.Errorf("error object = %v", m)
				}
				if src, ok := m["source"].(map[string]any); !ok || len(src) != 1 {
					t.Errorf("source = %v", m["source"])
				}
				if dig(t, m, "source", "pointer") == tc.pointer && strings.Contains(m["detail"].(string), tc.detail) {
					found = true
				}
			}
			if !found {
				t.Errorf("no error with pointer %q containing %q: %s", tc.pointer, tc.detail, r.Body)
			}
		})
	}
	// boundary: exactly 365 days is accepted
	ok := body(`{"name":"x","starts_at":"2026-11-12T06:00:00Z","ends_at":"2027-11-12T06:00:00Z"}`, good)
	wantStatus(t, api(t, s, tok, "POST", "/v3/keychains/custom", ok), 201)
	wantStatus(t, api(t, s, tok, "POST", "/v3/keychains/custom", "{not json"), 400)
}

func TestRealValidationBodies(t *testing.T) {
	s, tok := fixedServer(t)
	rels := `{"tenant":{"data":{"type":"tenants","id":"7754340"}},"access_points":{"data":[{"type":"access_points","id":"28821"}]}}`
	post := func(starts, ends string) reply {
		body := `{"data":{"type":"keychains","attributes":{"name":"x","starts_at":"` + starts + `","ends_at":"` + ends + `"},"relationships":` + rels + `}}`
		return api(t, s, tok, "POST", "/v3/keychains/custom", body)
	}
	r := post("2026-11-12T06:00:00Z", "2026-11-12T05:00:00Z")
	wantStatus(t, r, 400)
	want := `{"errors":[{"source":{"pointer":"/data/attributes/starts_at"},"detail":"Start time must be before the end time"},{"source":{"pointer":"/data/attributes/ends_at"},"detail":"End time must be after the start time"}]}`
	if !jsonEqual(t, r.Body, want) {
		t.Errorf("end before start body = %s", r.Body)
	}
	r = post("2026-11-12T06:00:00Z", "2027-11-13T06:00:00Z")
	wantStatus(t, r, 400)
	want = `{"errors":[{"source":{"pointer":"/data/attributes/ends_at"},"detail":"cannot exceed 365 days from start date"}]}`
	if !jsonEqual(t, r.Body, want) {
		t.Errorf("too long body = %s", r.Body)
	}
}

func jsonEqual(t *testing.T, got []byte, want string) bool {
	t.Helper()
	var a, b any
	if err := json.Unmarshal(got, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(want), &b); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(a, b)
}

func TestGuestPassPatchIsHTML404(t *testing.T) {
	s, tok := fixedServer(t)
	kid := s.Seed().ActiveKeychainIDs[0]
	patch := `{"data":{"type":"keychains","attributes":{"name":"Renamed"}}}`
	for _, p := range []string{"custom", "recurring"} {
		r := api(t, s, tok, "PATCH", "/v3/keychains/"+p+"/"+kid, patch)
		wantStatus(t, r, 404)
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") || !strings.Contains(string(r.Body), "<html") {
			t.Errorf("%s: content type %q, body %s", p, ct, r.Body)
		}
	}
	if got := s.Keychains()[0]; got.Name == "Renamed" {
		t.Error("guest pass was renamed")
	}
}

func TestAPITokenLifecycle(t *testing.T) {
	now := fixedNow
	s := newTestServer(t, WithClock(func() time.Time { return now }), WithAPITokenTTL(time.Hour))
	tk := login(t, s)
	get := func(tok string) reply { return api(t, s, tok, "GET", "/v3/access_codes?page[size]=1", nil) }
	wantStatus(t, get(tk.API), 200)

	r := get("")
	wantStatus(t, r, 401)
	if r.Header.Get("WWW-Authenticate") == "" || r.JSON(t)["errors"] == nil {
		t.Errorf("401 = %v %s", r.Header, r.Body)
	}
	wantStatus(t, get(tk.Access), 401) // OAuth token on an API endpoint

	now = now.Add(61 * time.Minute)
	wantStatus(t, get(tk.API), 401)
	// the OAuth token still works for a new denizen login
	api2 := denizenLogin(t, s, tk.Access)
	wantStatus(t, get(api2), 200)

	s.RevokeAPITokens()
	wantStatus(t, get(api2), 401)
	wantStatus(t, gql(t, s, api2, "CurrentUser", nil), 401)

	// logout revokes the token
	api3 := denizenLogin(t, s, tk.Access)
	r = api(t, s, api3, "DELETE", "/denizen/v1/logout", nil)
	wantStatus(t, r, 200)
	if len(r.Body) != 0 || r.Header.Get("Content-Type") != "text/html" {
		t.Errorf("logout = %q %v", r.Body, r.Header)
	}
	wantStatus(t, get(api3), 401)

	// denizen login with a bad or expired OAuth token
	b := []byte(`{"access_token":"bad","device":{}}`)
	wantStatus(t, do(t, newClient(), "POST", s.URL()+"/denizen/v1/login", b, map[string]string{"Content-Type": "application/json"}), 401)
	s2 := newTestServer(t, WithClock(func() time.Time { return now }), WithTokenTTL(time.Minute))
	tk2 := login(t, s2)
	now = now.Add(2 * time.Minute)
	b = []byte(`{"access_token":"` + tk2.Access + `","device":{}}`)
	wantStatus(t, do(t, newClient(), "POST", s2.URL()+"/denizen/v1/login", b, map[string]string{"Content-Type": "application/json"}), 401)
}

func TestUnlock(t *testing.T) {
	s, tok := fixedServer(t)
	r := postFixture(t, s, tok, "unlock/post-access-point-200", nil)
	wantStatus(t, r, 200)
	id := r.JSON(t)["requestId"].(string)
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(id) {
		t.Errorf("requestId = %q", id)
	}
	us := s.Unlocks()
	if len(us) != 1 || us[0].RequestID != id || us[0].AccessPointID != "prod-access_point-12921" || us[0].Source != "mobile_app" {
		t.Errorf("unlocks = %+v", us)
	}
	gr := gql(t, s, tok, "TenantDoorReleases", map[string]any{"tenantIds": []string{s.Seed().TenantGlobalID}, "after": ""})
	first := dig(t, nodes0(t, gr), "doorReleases", "nodes", 0)
	if dig(t, first, "accessPoint", "name") != "Front Door" {
		t.Errorf("first release = %v", first)
	}

	post := func(body string) reply { return api(t, s, tok, "POST", "/v1/access-point", body) }
	wantStatus(t, post(`{"accessPointId":"prod-access_point-999","tenantId":"prod-tenant-7754340"}`), 404)
	wantStatus(t, post(`{"accessPointId":"prod-access_point-12921","tenantId":"prod-tenant-1"}`), 403)
	wantStatus(t, post(`{"accessPointId":"12921","tenantId":"prod-tenant-7754340"}`), 400)
	wantStatus(t, post(`{"accessPointId":"prod-tenant-7754340","tenantId":"prod-tenant-7754340"}`), 400)
	wantStatus(t, post(`nope`), 400)
	wantStatus(t, api(t, s, "bad", "POST", "/v1/access-point", `{}`), 401)
	if len(s.Unlocks()) != 1 {
		t.Error("failed unlocks must not be recorded")
	}
}

func TestPushDevices(t *testing.T) {
	s, tok := fixedServer(t)
	f := loadFixture(t, "rest/post-mobile-users-devices-200")
	form := formFromFixture(t, f.reqJSON())
	h := map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}
	r := do(t, newClient(), "POST", s.URL()+"/mobile/v4/users/devices", []byte(form.Encode()), h)
	wantStatus(t, r, 200)
	d := r.JSON(t)["data"].(map[string]any)
	a := attrs(t, d)
	id := d["id"].(string)
	if d["type"] != "user_device_apples" || a["graphql_id"] != "prod-user_device_apple-"+id || a["voip_token"] != "FAKE_VOIP_TOKEN" ||
		fmt.Sprint(a["locales"]) != "[en-US]" || a["development"] != false || a["call_notification_push_type"] != "voip" {
		t.Errorf("device = %v", d)
	}
	if dig(t, d, "relationships", "user", "data", "id") != s.Seed().UserID {
		t.Errorf("user rel = %v", d["relationships"])
	}
	r = do(t, newClient(), "PATCH", s.URL()+"/mobile/v4/users/devices/"+id, formBody("device[client]", "iphone"), h)
	wantStatus(t, r, 200)
	if attrs(t, r.JSON(t)["data"])["token"] != "FAKE_PUSH_TOKEN" {
		t.Errorf("PATCH body = %s", r.Body)
	}
	wantStatus(t, do(t, newClient(), "PATCH", s.URL()+"/mobile/v4/users/devices/1", formBody("device[client]", "iphone"), h), 404)
	r = do(t, newClient(), "DELETE", s.URL()+"/mobile/v4/users/devices/"+id, nil, h)
	wantStatus(t, r, 204)
	wantStatus(t, do(t, newClient(), "DELETE", s.URL()+"/mobile/v4/users/devices/"+id, nil, h), 404)
	wantStatus(t, do(t, newClient(), "POST", s.URL()+"/mobile/v4/users/devices", []byte(form.Encode()), map[string]string{"Content-Type": h["Content-Type"]}), 401)
}

func TestUnknownRoute(t *testing.T) {
	s, tok := fixedServer(t)
	wantStatus(t, api(t, s, tok, "GET", "/v3/nope", nil), 404)
	wantStatus(t, api(t, s, tok, "GET", "/nope", nil), 404)
	r := api(t, s, tok, "PATCH", "/v3/keychains/custom/1", `{}`)
	wantStatus(t, r, 404)
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") {
		t.Errorf("unknown /v3 route content type = %q", r.Header.Get("Content-Type"))
	}
}

func TestConcurrentUse(t *testing.T) {
	s, tok := fixedServer(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				body := fmt.Sprintf(`{"data":{"type":"keychains","attributes":{"name":"p%d-%d","starts_at":"2026-11-12T05:00:00Z","ends_at":"2026-11-12T06:00:00Z","recipients":[{"name":"G","deliver_to":"g%d@example.com"}]},
				"relationships":{"tenant":{"data":{"type":"tenants","id":"7754340"}},"access_points":{"data":[{"type":"access_points","id":"28821"}]}}}}`, i, j, i)
				if r := api(t, s, tok, "POST", "/v3/keychains/custom", body); r.StatusCode != http.StatusCreated {
					t.Errorf("create: %d", r.StatusCode)
				}
				api(t, s, tok, "GET", "/v3/access_codes?include=virtual_keys", nil)
				_ = s.Keychains()
				_ = s.Requests()
			}
		}(i)
	}
	wg.Wait()
	if n := len(s.SentDeliveries()); n != 40 {
		t.Errorf("deliveries = %d", n)
	}
	pins := map[string]bool{}
	for _, k := range s.Keychains() {
		for _, v := range k.VirtualKeys {
			if pins[v.PIN] {
				t.Fatalf("duplicate PIN %s", v.PIN)
			}
			pins[v.PIN] = true
		}
	}
}

func TestSeedIsConsistent(t *testing.T) {
	s := newTestServer(t)
	sd := s.Seed()
	if sd.TenantGlobalID != "prod-tenant-7754340" || sd.TimeZone != "America/Los_Angeles" || len(sd.AccessPoints) != 7 || len(sd.VirtualKeyAccessPoints()) != 6 {
		t.Errorf("seed = %+v", sd)
	}
	if ap, ok := sd.AccessPointByName("Front Door"); !ok || ap.GlobalID != "prod-access_point-12921" {
		t.Errorf("Front Door = %+v", ap)
	}
	if len(sd.ActiveKeychainIDs) != 6 || len(sd.ExpiredKeychainIDs) != 24 || sd.DeliveryPassID != "88220723" {
		t.Errorf("passes: %v / %d", sd.ActiveKeychainIDs, len(sd.ExpiredKeychainIDs))
	}
	if len(s.SentDeliveries()) != 0 {
		t.Error("seeded passes must not appear as sent deliveries")
	}
	var buf strings.Builder
	_ = json.MarshalWrite(&buf, sd)
	if buf.Len() == 0 {
		t.Error("seed does not marshal")
	}
}

// A pass that has not started yet is listed as active (as on the real
// server): only ends_at decides between active and expired.
func TestFuturePassIsActive(t *testing.T) {
	s, tok := fixedServer(t)
	body := `{"data":{"type":"keychains","attributes":{"name":"Test Future","starts_at":"2027-07-01T07:00:00Z","ends_at":"2027-07-01T09:00:00Z"},
		"relationships":{"tenant":{"data":{"type":"tenants","id":"7754340"}},"access_points":{"data":[{"type":"access_points","id":"28821"}]}}}}`
	r := api(t, s, tok, "POST", "/v3/keychains/custom", body)
	wantStatus(t, r, 201)
	id := r.JSON(t)["data"].(map[string]any)["id"].(string)

	listed := func(status string) bool {
		resp := api(t, s, tok, "GET", "/v3/access_codes?filter[status]="+status+"&page[size]=100", nil)
		wantStatus(t, resp, 200)
		for _, d := range resp.JSON(t)["data"].([]any) {
			if d.(map[string]any)["id"] == id {
				return true
			}
		}
		return false
	}
	if !listed("active") {
		t.Error("future pass missing from active list")
	}
	if listed("expired") {
		t.Error("future pass listed as expired")
	}
}
