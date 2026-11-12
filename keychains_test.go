package butterflymx

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stevenmirabito/butterflymx-go/butterflymxtest"
)

// ---- shared helpers (used by all rest*_test.go files) ------------------------

// restTestReq is a request seen by a restTestServer.
type restTestReq struct {
	Method, Path string
	Query        url.Values
	Header       http.Header
	Body         []byte
}

// restTestServer starts a TLS server whose handler is h; it records every
// request and returns them through the accessor.
func restTestServer(t *testing.T, h func(r restTestReq) (int, []byte)) (*httptest.Server, func() []restTestReq) {
	t.Helper()
	var (
		mu   sync.Mutex
		seen []restTestReq
	)
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		req := restTestReq{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Header: r.Header.Clone(), Body: b}
		mu.Lock()
		seen = append(seen, req)
		mu.Unlock()
		status, body := h(req)
		if len(body) > 0 {
			w.Header().Set("Content-Type", "application/vnd.api+json; charset=utf-8")
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
	return srv, func() []restTestReq {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

// restTestFixture returns the whole decoded fixture testdata/rest/<name>.json.
func restTestFixture(t testing.TB, name string) (reqBody any, status int, respBody []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "rest", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Request struct {
			Body any `json:"body"`
		} `json:"request"`
		Response struct {
			Status int            `json:"status"`
			Body   jsontext.Value `json:"body"`
		} `json:"response"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f.Request.Body, f.Response.Status, f.Response.Body
}

func restTestRespBody(t testing.TB, name string) []byte {
	t.Helper()
	return fixtureBody(t, "rest/"+name+".json")
}

func restTestReqBody(t testing.TB, name string) any {
	t.Helper()
	b, _, _ := restTestFixture(t, name)
	return b
}

// restTestEqualJSON compares a request body with an expected JSON value,
// independent of key order.
func restTestEqualJSON(t testing.TB, got []byte, want any) {
	t.Helper()
	var g any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("request body is not JSON: %v\n%s", err, got)
	}
	if !reflect.DeepEqual(g, want) {
		gb, _ := json.Marshal(g, json.Deterministic(true))
		wb, _ := json.Marshal(want, json.Deterministic(true))
		t.Fatalf("request body mismatch\n got: %s\nwant: %s", gb, wb)
	}
}

// restTestMutate deep-copies v through JSON and lets f modify it.
func restTestMutate(t testing.TB, v any, f func(m map[string]any)) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	f(out)
	return out
}

func restTestDig(m any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m = m.(map[string]any)[k]
		case int:
			m = m.([]any)[k]
		}
	}
	return m
}

func restTestTenant(n ID) GlobalID { return NewGlobalID("prod", TypeTenant, n) }

func restTestAPs(ns ...ID) []GlobalID {
	var out []GlobalID
	for _, n := range ns {
		out = append(out, NewGlobalID("prod", TypeAccessPoint, n))
	}
	return out
}

func restTestParseTime(t testing.TB, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func restTestErrIs(t testing.TB, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want errors.Is %v", err, target)
	}
}

type restTestWorld struct {
	s      *butterflymxtest.Server
	c      *Client
	seed   butterflymxtest.Seed
	tenant GlobalID
	aps    []GlobalID // virtual-key doors
	loc    *time.Location
}

func restTestNewWorld(t *testing.T, opts ...butterflymxtest.Option) *restTestWorld {
	t.Helper()
	c, s := newFakeClient(t, opts...)
	seed := s.Seed()
	tenant, err := ParseGlobalID(seed.TenantGlobalID)
	if err != nil {
		t.Fatal(err)
	}
	w := &restTestWorld{s: s, c: c, seed: seed, tenant: tenant}
	for _, a := range seed.VirtualKeyAccessPoints() {
		g, err := ParseGlobalID(a.GlobalID)
		if err != nil {
			t.Fatal(err)
		}
		w.aps = append(w.aps, g)
	}
	if len(w.aps) < 2 {
		t.Fatalf("need two virtual-key doors, have %d", len(w.aps))
	}
	if w.loc, err = time.LoadLocation(seed.TimeZone); err != nil {
		t.Fatal(err)
	}
	return w
}

func restTestIDs(ks []Keychain) []ID {
	out := make([]ID, len(ks))
	for i, k := range ks {
		out[i] = k.ID
	}
	return out
}

func restTestHas(ks []Keychain, id ID) bool {
	return slices.ContainsFunc(ks, func(k Keychain) bool { return k.ID == id })
}

func restTestSeedID(t testing.TB, s string) ID {
	t.Helper()
	id, err := ParseID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// ---- request shape and decode tests ------------------------------------------

func TestRESTCreateKeychainCustomShape(t *testing.T) {
	srv, reqs := restTestServer(t, func(restTestReq) (int, []byte) {
		return http.StatusCreated, restTestRespBody(t, "post-keychains-custom-201")
	})
	c, _ := newTestClient(t, srv, nil)
	k, err := c.CreateKeychain(context.Background(), CreateKeychainParams{
		TenantID:       restTestTenant(7754340),
		AccessPointIDs: restTestAPs(51380, 85679, 27188, 28821, 61152, 12921),
		Name:           "Test",
		Schedule: CustomSchedule{
			StartsAt: restTestParseTime(t, "2026-11-12T05:00:00Z"),
			// A non-UTC instant must still be sent in UTC.
			EndsAt: restTestParseTime(t, "2026-11-11T22:00:00-08:00"),
		},
		Recipients: []Recipient{EmailRecipient("Resident Example", "resident@example.com")},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := reqs()
	if len(got) != 1 || got[0].Method != http.MethodPost || got[0].Path != "/v3/keychains/custom" {
		t.Fatalf("requests = %+v", got)
	}
	restTestEqualJSON(t, got[0].Body, restTestReqBody(t, "post-keychains-custom-201"))
	if ct := got[0].Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}

	if k.ID != 85303961 || k.Name != "Test" || k.Kind != KindCustom {
		t.Errorf("keychain = %+v", k)
	}
	if !k.StartsAt.Equal(restTestParseTime(t, "2026-11-12T05:00:00Z")) || !k.EndsAt.Equal(restTestParseTime(t, "2026-11-12T06:00:00Z")) {
		t.Errorf("window = %v - %v", k.StartsAt, k.EndsAt)
	}
	if k.StartDate != (Date{2026, 11, 11}) || k.EndDate != (Date{2026, 11, 11}) ||
		k.TimeFrom != (TimeOfDay{21, 0}) || k.TimeTo != (TimeOfDay{22, 0}) || len(k.Weekdays) != 0 {
		t.Errorf("derived fields = %v %v %v %v %v", k.StartDate, k.EndDate, k.TimeFrom, k.TimeTo, k.Weekdays)
	}
	if len(k.VirtualKeys) != 1 {
		t.Fatalf("virtual keys = %d", len(k.VirtualKeys))
	}
	vk := k.VirtualKeys[0]
	if vk.ID != 44122212 || vk.Name != "Resident Example" || vk.Email != "resident@example.com" || vk.SMSNumber != "" ||
		vk.PIN.Reveal() != "161803" || !strings.Contains(vk.QRCodeURL, "qr_code_") ||
		!strings.Contains(vk.InstructionsURL, "/public/virtual_keys/44122212/") || vk.SentAt != nil || vk.UsedAt != nil {
		t.Errorf("virtual key = %+v", vk)
	}
	want := []KeychainDevice{
		{ID: 50410, Type: "cloud_keyz_controllers", Name: "Bike Room & Garage Gate", BuildingID: 78323},
		{ID: 18461, Type: "cloud_keyz_controllers", Name: "Front Door & Stairwell Door", BuildingID: 78323},
		{ID: 38211, Type: "panels", Name: "Main Entrance", BuildingID: 78323},
		{ID: 13673, Type: "cloud_keyz_controllers", Name: "Side Door", BuildingID: 78323},
	}
	if !reflect.DeepEqual(k.Devices, want) {
		t.Errorf("devices = %+v", k.Devices)
	}
	if cs, ok := k.Schedule().(CustomSchedule); !ok || !cs.StartsAt.Equal(k.StartsAt) {
		t.Errorf("Schedule() = %#v", k.Schedule())
	}
}

func TestRESTCreateKeychainRecurringShape(t *testing.T) {
	srv, reqs := restTestServer(t, func(restTestReq) (int, []byte) {
		return http.StatusCreated, restTestRespBody(t, "post-keychains-recurring-201")
	})
	c, _ := newTestClient(t, srv, nil)
	k, err := c.CreateKeychain(context.Background(), CreateKeychainParams{
		TenantID:       restTestTenant(7754340),
		AccessPointIDs: restTestAPs(28821, 61152, 12921, 28821), // duplicate dropped
		Name:           "Test Recurring",
		Schedule: RecurringSchedule{
			Weekdays: []Weekday{Monday, Wednesday, Friday}, From: TimeOfDay{9, 0}, To: TimeOfDay{17, 0},
			StartDate: Date{2026, 11, 11}, EndDate: Date{2026, 11, 30},
		},
		Recipients: []Recipient{EmailRecipient("Resident Example", "resident@example.com")},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := reqs()
	if len(got) != 1 || got[0].Path != "/v3/keychains/recurring" {
		t.Fatalf("requests = %+v", got)
	}
	restTestEqualJSON(t, got[0].Body, restTestReqBody(t, "post-keychains-recurring-201"))

	if k.Kind != KindRecurring || !slices.Equal(k.Weekdays, []Weekday{Monday, Wednesday, Friday}) ||
		k.TimeFrom != (TimeOfDay{9, 0}) || k.TimeTo != (TimeOfDay{17, 0}) ||
		k.StartDate != (Date{2026, 11, 11}) || k.EndDate != (Date{2026, 11, 30}) ||
		!k.StartsAt.Equal(restTestParseTime(t, "2026-11-11T17:00:00Z")) || !k.EndsAt.Equal(restTestParseTime(t, "2026-12-01T01:00:00Z")) {
		t.Errorf("keychain = %+v", k)
	}
	rs, ok := k.Schedule().(RecurringSchedule)
	if !ok || rs.From != k.TimeFrom || !slices.Equal(rs.Weekdays, k.Weekdays) {
		t.Errorf("Schedule() = %#v", k.Schedule())
	}
}

func TestRESTListDecode(t *testing.T) {
	srv, reqs := restTestServer(t, func(restTestReq) (int, []byte) {
		return http.StatusOK, restTestRespBody(t, "get-access-codes-active-200-baseline")
	})
	c, _ := newTestClient(t, srv, nil)
	ks, err := c.Keychains(context.Background(), restTestTenant(7754340), KeychainFilter{})
	if err != nil {
		t.Fatal(err)
	}
	got := reqs()
	if len(got) != 1 || got[0].Path != "/v3/access_codes" {
		t.Fatalf("requests = %+v", got)
	}
	q := got[0].Query
	for k, v := range map[string]string{
		"filter[tenant]": "7754340", "filter[status]": "active", "page[size]": "20", "page[number]": "1",
		"include": "devices,virtual_keys,virtual_keys.door_releases,virtual_keys.door_releases.panel",
	} {
		if q.Get(k) != v {
			t.Errorf("query %s = %q, want %q", k, q.Get(k), v)
		}
	}
	if len(ks) != 6 {
		t.Fatalf("keychains = %d, want 6", len(ks))
	}
	var releases, panels, keys int
	for _, k := range ks {
		if k.ID == 0 || k.Name == "" || k.Kind == "" || k.StartsAt.IsZero() || len(k.Devices) == 0 {
			t.Errorf("incomplete keychain %+v", k)
		}
		for _, vk := range k.VirtualKeys {
			keys++
			if !vk.PIN.Valid() {
				t.Errorf("key %d has PIN %q", vk.ID, vk.PIN.Reveal())
			}
			for _, r := range vk.Releases {
				releases++
				if r.ReleaseMethod == "" || r.LoggedAt.IsZero() {
					t.Errorf("incomplete release %+v", r)
				}
				if r.Panel != nil {
					panels++
					if r.Panel.Type != "panels" || r.Panel.Name == "" {
						t.Errorf("panel = %+v", r.Panel)
					}
				}
			}
		}
	}
	if keys == 0 || releases == 0 || panels == 0 {
		t.Errorf("keys=%d releases=%d panels=%d, want all > 0", keys, releases, panels)
	}
}

func TestRESTListPaginationAndKindFilter(t *testing.T) {
	handler := func(r restTestReq) (int, []byte) {
		switch r.Query.Get("page[number]") {
		case "1": // has links.next
			return http.StatusOK, restTestRespBody(t, "get-access-codes-expired-200")
		case "2": // links.next is null
			return http.StatusOK, restTestRespBody(t, "get-access-codes-active-200-baseline")
		}
		return http.StatusInternalServerError, nil
	}
	srv, reqs := restTestServer(t, handler)
	c, _ := newTestClient(t, srv, nil)
	ctx := context.Background()

	ks, err := c.Keychains(ctx, restTestTenant(7754340), KeychainFilter{Status: StatusExpired})
	if err != nil {
		t.Fatal(err)
	}
	if len(ks) != 26 {
		t.Errorf("keychains = %d, want 20 + 6", len(ks))
	}
	got := reqs()
	if len(got) != 2 || got[0].Query.Get("page[number]") != "1" || got[1].Query.Get("page[number]") != "2" ||
		got[0].Query.Get("filter[status]") != "expired" {
		t.Errorf("requests = %+v", got)
	}

	// Kind filter is applied client-side.
	dp, err := c.Keychains(ctx, restTestTenant(7754340), KeychainFilter{Status: StatusExpired, Kinds: []KeychainKind{KindDeliveryPass}, PageSize: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(dp) == 0 || len(dp) >= len(ks) {
		t.Errorf("delivery passes = %d of %d", len(dp), len(ks))
	}
	for _, k := range dp {
		if k.Kind != KindDeliveryPass {
			t.Errorf("kind = %q", k.Kind)
		}
	}

	// Lazy iteration stops fetching when the consumer stops.
	before := len(reqs())
	n := 0
	for k, err := range c.KeychainsSeq(ctx, restTestTenant(7754340), KeychainFilter{}) {
		if err != nil {
			t.Fatal(err)
		}
		_ = k
		if n++; n == 3 {
			break
		}
	}
	if n != 3 || len(reqs())-before != 1 {
		t.Errorf("n = %d, extra requests = %d, want 3 and 1", n, len(reqs())-before)
	}
}

func TestRESTListErrors(t *testing.T) {
	srv, reqs := restTestServer(t, func(r restTestReq) (int, []byte) {
		if r.Query.Get("page[number]") == "2" {
			return http.StatusBadRequest, []byte(`{"errors":[{"detail":"nope"}]}`)
		}
		return http.StatusOK, restTestRespBody(t, "get-access-codes-expired-200")
	})
	c, _ := newTestClient(t, srv, nil)

	// A failing second page surfaces as the last element of the sequence.
	var seen int
	var last error
	for _, err := range c.KeychainsSeq(context.Background(), restTestTenant(7754340), KeychainFilter{}) {
		if err != nil {
			last = err
			break
		}
		seen++
	}
	if seen != 20 {
		t.Errorf("seen = %d", seen)
	}
	restTestErrIs(t, last, ErrValidation)
	var apiErr *Error
	if !errors.As(last, &apiErr) || len(apiErr.APIErrors) != 1 || apiErr.Op != "Keychains" {
		t.Errorf("error = %#v", last)
	}

	n := len(reqs())
	if _, err := c.Keychains(context.Background(), NewGlobalID("prod", TypeAccessPoint, 1), KeychainFilter{}); !errors.Is(err, ErrIDType) {
		t.Errorf("wrong id type: err = %v", err)
	}
	if _, err := c.Keychains(context.Background(), GlobalID{}, KeychainFilter{}); !errors.Is(err, ErrIDType) {
		t.Errorf("zero id: err = %v", err)
	}
	if len(reqs()) != n {
		t.Error("a request was sent for an invalid tenant id")
	}
}

func TestRESTGetKeychainDecode(t *testing.T) {
	srv, reqs := restTestServer(t, func(restTestReq) (int, []byte) {
		return http.StatusOK, restTestRespBody(t, "get-keychains-custom-200-second-key-added")
	})
	c, _ := newTestClient(t, srv, nil)
	k, err := c.Keychain(context.Background(), 85303961)
	if err != nil {
		t.Fatal(err)
	}
	got := reqs()
	if len(got) != 1 || got[0].Method != http.MethodGet || got[0].Path != "/v3/keychains/85303961" {
		t.Fatalf("requests = %+v", got)
	}
	if inc := got[0].Query.Get("include"); inc != "virtual_keys,devices,virtual_keys.door_releases,virtual_keys.door_releases.panel" {
		t.Errorf("include = %q", inc)
	}
	if len(k.VirtualKeys) != 2 {
		t.Fatalf("virtual keys = %d, want 2", len(k.VirtualKeys))
	}
	var sms, email int
	for _, vk := range k.VirtualKeys {
		if vk.SMSNumber != "" {
			sms++
			if !strings.HasPrefix(vk.SMSNumber, "+") {
				t.Errorf("sms number = %q", vk.SMSNumber)
			}
		}
		if vk.Email != "" {
			email++
		}
	}
	if sms != 1 || email != 1 {
		t.Errorf("sms=%d email=%d", sms, email)
	}
	// Devices were not included in this fixture: they are stubs with IDs.
	for _, d := range k.Devices {
		if d.ID == 0 || d.Type == "" {
			t.Errorf("device stub = %+v", d)
		}
	}
	if _, err := c.Keychain(context.Background(), 0); !errors.Is(err, ErrValidation) {
		t.Errorf("zero id: err = %v", err)
	}
}

func TestRESTDecodeLenient(t *testing.T) {
	body := `{"data":{"id":"5","type":"keychains","attributes":{
		"name":null,"kind":"time_travel","starts_at":null,"ends_at":"garbage","start_date":"x","end_date":null,
		"time_from":"25:99","time_to":null,"weekdays":["mon","Funday"],"allow_unit_access":null,"surprise":{"a":1}},
		"relationships":{"virtual_keys":{"data":[{"id":"9","type":"virtual_keys"}]},"devices":{"data":null},"owner":{"data":null}}},
		"included":[]}`
	srv, _ := restTestServer(t, func(restTestReq) (int, []byte) { return http.StatusOK, []byte(body) })
	c, _ := newTestClient(t, srv, nil)
	k, err := c.Keychain(context.Background(), 5)
	if err != nil {
		t.Fatal(err)
	}
	if k.Kind != "time_travel" || k.Name != "" || !k.StartsAt.IsZero() || !k.EndsAt.IsZero() || !k.StartDate.IsZero() ||
		k.TimeFrom != (TimeOfDay{}) || !slices.Equal(k.Weekdays, []Weekday{Monday, "Funday"}) {
		t.Errorf("keychain = %+v", k)
	}
	if k.Schedule() != nil {
		t.Errorf("Schedule() for an unknown kind = %#v, want nil", k.Schedule())
	}
	if len(k.VirtualKeys) != 1 || k.VirtualKeys[0].ID != 9 || k.VirtualKeys[0].PIN != "" {
		t.Errorf("virtual keys = %+v", k.VirtualKeys)
	}
	if len(k.Devices) != 0 {
		t.Errorf("devices = %+v", k.Devices)
	}
}

func TestRESTCreateNotRetried(t *testing.T) {
	srv, reqs := restTestServer(t, func(restTestReq) (int, []byte) { return http.StatusServiceUnavailable, nil })
	c, delays := newTestClient(t, srv, nil)
	_, err := c.CreateKeychain(context.Background(), CreateKeychainParams{
		TenantID: restTestTenant(1), AccessPointIDs: restTestAPs(2), Name: "x",
		Schedule:   CustomSchedule{StartsAt: time.Unix(1_800_000_000, 0), EndsAt: time.Unix(1_800_003_600, 0)},
		Recipients: []Recipient{EmailRecipient("A", "a@example.com")},
	})
	restTestErrIs(t, err, ErrServer)
	if len(reqs()) != 1 || len(*delays) != 0 {
		t.Errorf("requests = %d, retry delays = %d, want 1 and 0", len(reqs()), len(*delays))
	}
}

func TestRESTCreateKeychainValidation(t *testing.T) {
	srv, reqs := restTestServer(t, func(restTestReq) (int, []byte) { return http.StatusInternalServerError, nil })
	c, _ := newTestClient(t, srv, nil)
	good := func() CreateKeychainParams {
		return CreateKeychainParams{
			TenantID: restTestTenant(1), AccessPointIDs: restTestAPs(2), Name: "x",
			Schedule:   CustomSchedule{StartsAt: time.Unix(1_800_000_000, 0), EndsAt: time.Unix(1_800_003_600, 0)},
			Recipients: []Recipient{EmailRecipient("A", "a@example.com")},
		}
	}
	tests := []struct {
		name string
		mod  func(*CreateKeychainParams)
		want error
	}{
		{"tenant is wrong type", func(p *CreateKeychainParams) { p.TenantID = NewGlobalID("prod", TypeUnit, 1) }, ErrIDType},
		{"tenant zero", func(p *CreateKeychainParams) { p.TenantID = GlobalID{} }, ErrIDType},
		{"access point is wrong type", func(p *CreateKeychainParams) { p.AccessPointIDs = []GlobalID{NewGlobalID("prod", TypeTenant, 2)} }, ErrIDType},
		{"no access points", func(p *CreateKeychainParams) { p.AccessPointIDs = nil }, ErrValidation},
		{"blank name", func(p *CreateKeychainParams) { p.Name = "  " }, ErrValidation},
		{"nil schedule", func(p *CreateKeychainParams) { p.Schedule = nil }, ErrValidation},
		{"end before start", func(p *CreateKeychainParams) {
			p.Schedule = CustomSchedule{StartsAt: time.Unix(1_800_003_600, 0), EndsAt: time.Unix(1_800_000_000, 0)}
		}, ErrValidation},
		{"end equals start", func(p *CreateKeychainParams) {
			p.Schedule = CustomSchedule{StartsAt: time.Unix(1_800_000_000, 0), EndsAt: time.Unix(1_800_000_000, 5e8)}
		}, ErrValidation},
		{"bad recipient", func(p *CreateKeychainParams) { p.Recipients = []Recipient{EmailRecipient("A", "nope")} }, ErrValidation},
		{"recurring without weekdays", func(p *CreateKeychainParams) {
			p.Schedule = RecurringSchedule{From: TimeOfDay{9, 0}, To: TimeOfDay{17, 0}, StartDate: Date{2026, 1, 1}, EndDate: Date{2026, 1, 2}}
		}, ErrValidation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := good()
			tt.mod(&p)
			_, err := c.CreateKeychain(context.Background(), p)
			restTestErrIs(t, err, tt.want)
			var e *Error
			if !errors.As(err, &e) || e.Op != "CreateKeychain" || e.StatusCode != 0 {
				t.Errorf("error = %#v", err)
			}
		})
	}
	if n := len(reqs()); n != 0 {
		t.Errorf("%d requests were sent for invalid parameters", n)
	}
}

func TestRESTDeleteKeychain(t *testing.T) {
	srv, reqs := restTestServer(t, func(restTestReq) (int, []byte) { return http.StatusNoContent, nil })
	c, _ := newTestClient(t, srv, nil)
	if err := c.DeleteKeychain(context.Background(), 85303961); err != nil {
		t.Fatal(err)
	}
	got := reqs()
	if len(got) != 1 || got[0].Method != http.MethodDelete || got[0].Path != "/v3/keychains/85303961" || len(got[0].Body) != 0 {
		t.Errorf("requests = %+v", got)
	}
	restTestErrIs(t, c.DeleteKeychain(context.Background(), 0), ErrValidation)
}

// ---- integration against the fake -------------------------------------------

func TestRESTKeychainLifecycle(t *testing.T) {
	w := restTestNewWorld(t)
	ctx := context.Background()
	hour := time.Now().UTC().Truncate(time.Hour)

	// Create a custom pass; the server derives the building-local fields.
	start, end := hour.Add(2*time.Hour), hour.Add(5*time.Hour)
	custom, err := w.c.CreateKeychain(ctx, CreateKeychainParams{
		TenantID: w.tenant, AccessPointIDs: w.aps[:2], Name: "Alex (custom)",
		Schedule:   CustomSchedule{StartsAt: start, EndsAt: end},
		Recipients: []Recipient{EmailRecipient("Alex Guest", "alex@example.com")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if custom.Kind != KindCustom || custom.Name != "Alex (custom)" || !custom.StartsAt.Equal(start) || !custom.EndsAt.Equal(end) {
		t.Errorf("custom = %+v", custom)
	}
	ls, le := start.In(w.loc), end.In(w.loc)
	if custom.StartDate != DateOf(ls) || custom.EndDate != DateOf(le) ||
		custom.TimeFrom != (TimeOfDay{ls.Hour(), ls.Minute()}) || custom.TimeTo != (TimeOfDay{le.Hour(), le.Minute()}) {
		t.Errorf("derived local fields = %v %v %v %v, want %v %v", custom.StartDate, custom.EndDate, custom.TimeFrom, custom.TimeTo, ls, le)
	}
	if len(custom.VirtualKeys) != 1 || len(custom.Devices) == 0 {
		t.Fatalf("custom keys=%d devices=%d", len(custom.VirtualKeys), len(custom.Devices))
	}
	vk := custom.VirtualKeys[0]
	if !vk.PIN.Valid() || len(vk.PIN) != 6 || vk.QRCodeURL == "" || vk.InstructionsURL == "" ||
		vk.Email != "alex@example.com" || vk.Name != "Alex Guest" || vk.SentAt != nil {
		t.Errorf("virtual key = %+v", vk)
	}

	// Create a recurring pass (weekdays given out of order).
	today := DateOf(time.Now().In(w.loc))
	rec, err := w.c.CreateKeychain(ctx, CreateKeychainParams{
		TenantID: w.tenant, AccessPointIDs: w.aps[:1], Name: "Dog walker",
		Schedule: RecurringSchedule{
			Weekdays: []Weekday{Wednesday, Monday}, From: TimeOfDay{9, 0}, To: TimeOfDay{17, 30},
			StartDate: today.AddDays(1), EndDate: today.AddDays(30),
		},
		Recipients: []Recipient{SMSRecipient("Sam Walker", "(555) 555-0100")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Kind != KindRecurring || !slices.Equal(rec.Weekdays, []Weekday{Monday, Wednesday}) ||
		rec.TimeFrom != (TimeOfDay{9, 0}) || rec.TimeTo != (TimeOfDay{17, 30}) ||
		rec.StartDate != today.AddDays(1) || rec.EndDate != today.AddDays(30) {
		t.Errorf("recurring = %+v", rec)
	}
	if want := (TimeOfDay{9, 0}).On(today.AddDays(1), w.loc); !rec.StartsAt.Equal(want) {
		t.Errorf("recurring StartsAt = %v, want %v", rec.StartsAt, want)
	}
	if want := (TimeOfDay{17, 30}).On(today.AddDays(30), w.loc); !rec.EndsAt.Equal(want) {
		t.Errorf("recurring EndsAt = %v, want %v", rec.EndsAt, want)
	}
	if rec.VirtualKeys[0].SMSNumber != "+15555550100" || rec.VirtualKeys[0].Email != "" {
		t.Errorf("sms key = %+v", rec.VirtualKeys[0])
	}

	// List active: ours and the seeded ones are there; kinds filter works.
	active, err := w.c.Keychains(ctx, w.tenant, KeychainFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []ID{custom.ID, rec.ID} {
		if !restTestHas(active, id) {
			t.Errorf("active list lacks %d", id)
		}
	}
	for _, s := range w.seed.ActiveKeychainIDs {
		if !restTestHas(active, restTestSeedID(t, s)) {
			t.Errorf("active list lacks seeded %s", s)
		}
	}
	onlyRec, err := w.c.Keychains(ctx, w.tenant, KeychainFilter{Kinds: []KeychainKind{KindRecurring}})
	if err != nil {
		t.Fatal(err)
	}
	if !restTestHas(onlyRec, rec.ID) || restTestHas(onlyRec, custom.ID) {
		t.Errorf("recurring-only list = %v", restTestIDs(onlyRec))
	}
	// Small pages give the same list as the default page size.
	small, err := w.c.Keychains(ctx, w.tenant, KeychainFilter{PageSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(restTestIDs(small), restTestIDs(active)) {
		t.Errorf("paged list = %v, want %v", restTestIDs(small), restTestIDs(active))
	}

	// Get: the delivery has happened by now, and the key is the same.
	got, err := w.c.Keychain(ctx, custom.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != custom.ID || len(got.VirtualKeys) != 1 || got.VirtualKeys[0].PIN != vk.PIN || got.VirtualKeys[0].SentAt == nil {
		t.Errorf("get = %+v", got)
	}
	if len(got.Devices) == 0 || got.Devices[0].Name == "" || got.Devices[0].BuildingID == 0 {
		t.Errorf("devices = %+v", got.Devices)
	}
	if dl := w.s.SentDeliveries(); len(dl) != 2 || dl[0].Channel != "email" || dl[1].Channel != "sms" || dl[1].To != "+15555550100" {
		t.Errorf("deliveries = %+v", dl)
	}

	// A door release shows up under the key.
	if err := w.s.AddDoorRelease(vk.ID.String(), w.seed.VirtualKeyAccessPoints()[0].ID); err != nil {
		t.Fatal(err)
	}
	if got, err = w.c.Keychain(ctx, custom.ID); err != nil {
		t.Fatal(err)
	}
	if rs := got.VirtualKeys[0].Releases; len(rs) != 1 || rs[0].ReleaseMethod != "virtual_key_pin" || rs[0].LoggedAt.IsZero() {
		t.Errorf("releases = %+v", rs)
	}

	// Add an SMS key, then revoke the first key.
	added, err := w.c.AddVirtualKeys(ctx, custom.ID, SMSRecipient("Bea", "315-555-0123"))
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 1 || added[0].SMSNumber != "+13155550123" || added[0].Name != "Bea" || !added[0].PIN.Valid() {
		t.Fatalf("added = %+v", added)
	}
	if err := w.c.RevokeVirtualKey(ctx, custom.ID, vk.ID); err != nil {
		t.Fatal(err)
	}
	if got, err = w.c.Keychain(ctx, custom.ID); err != nil {
		t.Fatal(err)
	}
	if len(got.VirtualKeys) != 1 || got.VirtualKeys[0].ID != added[0].ID {
		t.Errorf("keys after revoke = %+v", got.VirtualKeys)
	}
	restTestErrIs(t, w.c.RevokeVirtualKey(ctx, custom.ID, vk.ID), ErrNotFound)

	// Delete.
	if err := w.c.DeleteKeychain(ctx, custom.ID); err != nil {
		t.Fatal(err)
	}
	_, err = w.c.Keychain(ctx, custom.ID)
	restTestErrIs(t, err, ErrNotFound)
	restTestErrIs(t, w.c.DeleteKeychain(ctx, custom.ID), ErrNotFound)

	// Expired list: a pass in the past, plus the seeded expired ones.
	past, err := w.c.CreateKeychain(ctx, CreateKeychainParams{
		TenantID: w.tenant, AccessPointIDs: w.aps[:1], Name: "Last week",
		Schedule:   CustomSchedule{StartsAt: hour.Add(-48 * time.Hour), EndsAt: hour.Add(-24 * time.Hour)},
		Recipients: []Recipient{EmailRecipient("Old Guest", "old@example.com")},
	})
	if err != nil {
		t.Fatal(err)
	}
	expired, err := w.c.Keychains(ctx, w.tenant, KeychainFilter{Status: StatusExpired})
	if err != nil {
		t.Fatal(err)
	}
	if !restTestHas(expired, past.ID) || restTestHas(expired, rec.ID) {
		t.Errorf("expired list = %v", restTestIDs(expired))
	}
	for _, s := range w.seed.ExpiredKeychainIDs {
		if !restTestHas(expired, restTestSeedID(t, s)) {
			t.Errorf("expired list lacks seeded %s", s)
		}
	}
	active, err = w.c.Keychains(ctx, w.tenant, KeychainFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if restTestHas(active, past.ID) {
		t.Error("expired pass is in the active list")
	}
}

func TestRESTKeychainServerValidation(t *testing.T) {
	w := restTestNewWorld(t)
	ctx := context.Background()
	hour := time.Now().UTC().Truncate(time.Hour)
	ok := CreateKeychainParams{
		TenantID: w.tenant, AccessPointIDs: w.aps[:1], Name: "x",
		Schedule:   CustomSchedule{StartsAt: hour.Add(time.Hour), EndsAt: hour.Add(2 * time.Hour)},
		Recipients: []Recipient{EmailRecipient("A", "a@example.com")},
	}

	// Client-side failures send nothing.
	before := len(w.s.Requests())
	bad := ok
	bad.Schedule = CustomSchedule{StartsAt: hour.Add(2 * time.Hour), EndsAt: hour.Add(time.Hour)}
	_, err := w.c.CreateKeychain(ctx, bad)
	restTestErrIs(t, err, ErrValidation)
	bad = ok
	bad.Schedule = RecurringSchedule{Weekdays: []Weekday{Monday}, From: TimeOfDay{9, 0}, To: TimeOfDay{10, 0}, StartDate: Date{2026, 12, 2}, EndDate: Date{2026, 12, 1}}
	_, err = w.c.CreateKeychain(ctx, bad)
	restTestErrIs(t, err, ErrValidation)
	if n := len(w.s.Requests()); n != before {
		t.Errorf("%d requests sent for client-side failures", n-before)
	}

	// The server's 400 maps to ErrValidation and keeps the error objects.
	long := ok
	long.Schedule = CustomSchedule{StartsAt: hour.Add(time.Hour), EndsAt: hour.Add(time.Hour + 400*24*time.Hour)}
	_, err = w.c.CreateKeychain(ctx, long)
	restTestErrIs(t, err, ErrValidation)
	var e *Error
	if !errors.As(err, &e) || e.StatusCode != http.StatusBadRequest || len(e.APIErrors) == 0 ||
		e.APIErrors[0].Source == nil || !strings.HasSuffix(e.APIErrors[0].Source.Pointer, "ends_at") {
		t.Errorf("error = %#v", err)
	}

	// A door without the virtual-key capability is refused by the server.
	for _, a := range w.seed.AccessPoints {
		if a.VirtualKeys {
			continue
		}
		g, err := ParseGlobalID(a.GlobalID)
		if err != nil {
			t.Fatal(err)
		}
		nv := ok
		nv.AccessPointIDs = []GlobalID{g}
		_, err = w.c.CreateKeychain(ctx, nv)
		restTestErrIs(t, err, ErrValidation)
		break
	}
	if n := len(w.s.Keychains()); n != len(w.seed.ActiveKeychainIDs)+len(w.seed.ExpiredKeychainIDs) {
		t.Errorf("failed creates left %d keychains", n)
	}
}
