package butterflymxtest

import (
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// This file replays the pseudonymized exchanges in testdata/ against the fake
// and checks that every response has the same status, the same selected
// headers and the same JSON shape as the recorded one.
//
// Shape comparison rules (see shapeDiff):
//   - objects must have exactly the same keys, recursively;
//   - scalars must have the same JSON type (string, number, bool);
//   - null on either side matches anything (the fixture only shows one
//     instance of a nullable field);
//   - an empty array on either side matches any array (the capture or the
//     fake had no element to show);
//   - otherwise every element shape on one side must be matched by some
//     element on the other side.
//
// HTML and turbo-stream bodies are compared structurally with htmlSkeleton
// (field names, form actions, links, headings) because their values are
// random CSRF tokens.
//
// The fixtures are replayed as one session in the order of the capture, with
// the fixture IDs mapped to the IDs the fake generates. No fixture is
// skipped; the replay needs a fixed clock (fixedNow, the instant of the
// delivery-pass creation in the capture) so that derived timestamps can even
// be compared exactly for the create exchanges.

// shapeDiff returns the differences between the shape of want (a fixture) and
// got (a fake response).
func shapeDiff(path string, want, got any) []string {
	if want == nil || got == nil {
		return nil
	}
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return []string{fmt.Sprintf("%s: want object, got %T", path, got)}
		}
		var out []string
		for k := range w {
			if _, ok := g[k]; !ok {
				out = append(out, fmt.Sprintf("%s: missing key %q", path, k))
			}
		}
		for k := range g {
			if _, ok := w[k]; !ok {
				out = append(out, fmt.Sprintf("%s: unexpected key %q", path, k))
			}
		}
		for k, wv := range w {
			if gv, ok := g[k]; ok {
				out = append(out, shapeDiff(path+"."+k, wv, gv)...)
			}
		}
		sort.Strings(out)
		return out
	case []any:
		g, ok := got.([]any)
		if !ok {
			return []string{fmt.Sprintf("%s: want array, got %T", path, got)}
		}
		if len(w) == 0 || len(g) == 0 {
			return nil
		}
		var out []string
		covered := func(from, in []any, label string) {
			for i, x := range from {
				found := false
				for _, y := range in {
					if len(shapeDiff("", x, y)) == 0 {
						found = true
						break
					}
				}
				if !found {
					out = append(out, fmt.Sprintf("%s[%d]: no %s element has this shape (%s)", path, i, label, strings.Join(shapeDiff("", x, in[0]), "; ")))
				}
			}
		}
		covered(w, g, "fake")
		covered(g, w, "fixture")
		return out
	default:
		if reflect.TypeOf(want) != reflect.TypeOf(got) {
			return []string{fmt.Sprintf("%s: want %T, got %T", path, want, got)}
		}
		return nil
	}
}

func TestShapeDiffItself(t *testing.T) {
	d := func(a, b string) []string {
		var x, y any
		if err := json.Unmarshal([]byte(a), &x); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(b), &y); err != nil {
			t.Fatal(err)
		}
		return shapeDiff("$", x, y)
	}
	for _, ok := range [][2]string{
		{`{"a":1,"b":"x"}`, `{"b":"y","a":2}`},
		{`{"a":null}`, `{"a":"s"}`},
		{`{"a":[]}`, `{"a":[{"x":1}]}`},
		{`[{"a":1},{"b":2}]`, `[{"b":3},{"a":4},{"a":5}]`},
	} {
		if got := d(ok[0], ok[1]); len(got) != 0 {
			t.Errorf("%s vs %s: %v", ok[0], ok[1], got)
		}
	}
	for _, bad := range [][2]string{
		{`{"a":1}`, `{"a":"1"}`},
		{`{"a":1}`, `{"a":1,"b":2}`},
		{`{"a":1,"b":2}`, `{"a":1}`},
		{`[{"a":1}]`, `[{"a":1},{"c":1}]`},
		{`{"a":{}}`, `{"a":[]}`},
	} {
		if got := d(bad[0], bad[1]); len(got) == 0 {
			t.Errorf("%s vs %s: expected a difference", bad[0], bad[1])
		}
	}
}

var (
	reNameAttr   = regexp.MustCompile(`\bname="([^"]*)"`)
	reActionAttr = regexp.MustCompile(`\baction="([^"]*)"`)
	reHrefAttr   = regexp.MustCompile(`\bhref="([^"]*)"`)
	reHeading    = regexp.MustCompile(`(?s)<h[12][^>]*>\s*(.*?)\s*</h[12]>`)
	reErrText    = regexp.MustCompile(`(Two factor authentication failed\.|Invalid code, please try again or request a new code\.|Invalid email or password\.)`)
)

// htmlSkeleton lists the parts of an accounts page a client depends on.
func htmlSkeleton(body string) []string {
	set := map[string]bool{}
	add := func(kind string, re *regexp.Regexp) {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			set[kind+"="+strings.TrimSpace(m[1])] = true
		}
	}
	add("name", reNameAttr)
	add("action", reActionAttr)
	add("href", reHrefAttr)
	add("heading", reHeading)
	add("text", reErrText)
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type replay struct {
	t    *testing.T
	s    *Server
	c    *http.Client
	ids  map[string]string
	tags map[string]string // fixture name -> ETag of the replayed response
}

type sendOpts struct {
	token  string
	form   url.Values        // replaces the fixture's form body (merged on top when merge is set)
	merge  bool              // add form on top of the fixture's own form fields
	body   *string           // replaces the JSON body
	inm    string            // If-None-Match override
	header map[string]string // extra request headers
}

func (r *replay) send(f fixture, o sendOpts) reply {
	r.t.Helper()
	path := replaceIDs(f.Request.Path, r.ids)
	u := r.s.URL() + path
	if q := replaceIDs(f.queryString(), r.ids); q != "" {
		u += "?" + q
	}
	h := map[string]string{}
	for _, k := range []string{"accept", "content-type", "user-agent", "x-bmx-service"} {
		if v, ok := f.Request.Headers[k]; ok {
			h[k] = v
		}
	}
	if v, ok := f.Request.Headers["if-none-match"]; ok {
		h["if-none-match"] = v
	}
	if o.inm != "" {
		h["if-none-match"] = o.inm
	}
	if o.token != "" {
		h["Authorization"] = "Bearer " + o.token
	}
	for k, v := range o.header {
		h[k] = v
	}
	var body []byte
	ct := f.Request.Headers["content-type"]
	switch {
	case strings.HasPrefix(ct, "application/x-www-form-urlencoded"):
		form := url.Values{}
		if o.form == nil || o.merge {
			if raw := f.reqJSON(); raw != "" {
				form = formFromFixture(r.t, replaceIDs(raw, r.ids))
			}
		}
		for k, v := range o.form {
			form[k] = v
		}
		body = []byte(form.Encode())
	case o.body != nil:
		body = []byte(*o.body)
	default:
		body = []byte(replaceIDs(f.reqJSON(), r.ids))
	}
	return do(r.t, r.c, f.Request.Method, u, body, h)
}

// check compares status, headers and body of a reply with the fixture.
func (r *replay) check(f fixture, got reply) {
	r.t.Helper()
	t := r.t
	if got.StatusCode != f.Response.Status {
		t.Errorf("%s: status = %d, want %d\n%s", f.Name, got.StatusCode, f.Response.Status, got.Body)
		return
	}
	wantCT := f.Response.Headers["content-type"]
	if gotCT := got.Header.Get("Content-Type"); gotCT != wantCT {
		t.Errorf("%s: content-type = %q, want %q", f.Name, gotCT, wantCT)
	}
	if _, ok := f.Response.Headers["etag"]; ok && got.Header.Get("ETag") == "" {
		t.Errorf("%s: missing ETag", f.Name)
	}
	if _, ok := f.Response.Headers["location"]; ok && got.Header.Get("Location") == "" {
		t.Errorf("%s: missing Location", f.Name)
	}
	body := strings.TrimSpace(string(f.Response.Body))
	switch {
	case body == "null":
		if len(got.Body) != 0 {
			t.Errorf("%s: expected an empty body, got %q", f.Name, got.Body)
		}
	case strings.HasPrefix(body, `"`): // HTML or turbo-stream, stored as a JSON string
		var want string
		if err := json.Unmarshal([]byte(body), &want); err != nil {
			t.Fatal(err)
		}
		if w, g := htmlSkeleton(want), htmlSkeleton(string(got.Body)); !reflect.DeepEqual(w, g) {
			t.Errorf("%s: page structure differs\nfixture: %v\nfake:    %v", f.Name, w, g)
		}
	default:
		var want, gotv any
		if err := json.Unmarshal([]byte(body), &want); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(got.Body, &gotv); err != nil {
			t.Errorf("%s: response is not JSON: %v\n%s", f.Name, err, got.Body)
			return
		}
		for _, d := range shapeDiff("$", want, gotv) {
			t.Errorf("%s: %s", f.Name, d)
		}
	}
}

func (r *replay) step(rel string, o sendOpts, after func(f fixture, got reply)) {
	r.t.Helper()
	r.t.Run(rel, func(t *testing.T) {
		rr := *r
		rr.t = t
		f := loadFixture(t, rel)
		got := rr.send(f, o)
		rr.check(f, got)
		if et := got.Header.Get("ETag"); et != "" {
			r.tags[rel] = et
		}
		if after != nil && !t.Failed() {
			after(f, got)
		}
	})
}

func jsonOf(t *testing.T, r reply) map[string]any { t.Helper(); return r.JSON(t) }

func TestConformanceAccounts(t *testing.T) {
	s := newTestServer(t, WithClock(func() time.Time { return fixedNow }))
	r := &replay{t: t, s: s, c: newClient(), ids: map[string]string{}, tags: map[string]string{}}
	var meta, form, code string

	r.step("accounts/get-oauth-authorize-302-to-login", sendOpts{}, func(f fixture, got reply) {
		if !strings.HasSuffix(got.Header.Get("Location"), "/login/new") {
			t.Errorf("location = %q", got.Header.Get("Location"))
		}
	})
	r.step("accounts/get-login-new-200", sendOpts{}, func(f fixture, got reply) { meta, form = csrfTokens(t, got.Body) })
	r.step("accounts/post-login-303", sendOpts{
		merge: true, form: url.Values{"authenticity_token": {form}, "login[password]": {DefaultPassword}},
		header: map[string]string{"X-CSRF-Token": meta},
	}, func(f fixture, got reply) {
		want, _ := url.Parse(f.Response.Headers["location"])
		have, _ := url.Parse(got.Header.Get("Location"))
		if want.RequestURI() != have.RequestURI() {
			t.Errorf("location = %s, want path %s", have.RequestURI(), want.RequestURI())
		}
	})
	r.step("accounts/get-two-factor-new-200", sendOpts{}, func(f fixture, got reply) { meta, form = csrfTokens(t, got.Body) })

	bad := "000000"
	for totpValid(s.TOTPSecret(), bad, s.now()) {
		bad = "999999"
	}
	r.step("accounts/post-two-factor-422-wrong-code", sendOpts{
		merge: true, form: url.Values{"authenticity_token": {form}, "code": {bad}}, header: map[string]string{"X-CSRF-Token": meta},
	}, func(f fixture, got reply) { meta, form = csrfTokens(t, got.Body) })
	r.step("accounts/post-two-factor-200-turbo-stream", sendOpts{
		merge: true, form: url.Values{"authenticity_token": {form}, "code": {s.CurrentTOTP()}}, header: map[string]string{"X-CSRF-Token": meta},
	}, func(f fixture, got reply) {
		// With the capture's own authorize query the location is reproduced exactly.
		var want string
		if err := json.Unmarshal(f.Response.Body, &want); err != nil {
			t.Fatal(err)
		}
		if string(got.Body) != want {
			t.Errorf("turbo-stream\n got: %s\nwant: %s", got.Body, want)
		}
	})
	r.step("accounts/get-oauth-authorize-302-to-app", sendOpts{}, func(f fixture, got reply) {
		loc := got.Header.Get("Location")
		u, err := url.Parse(loc)
		if err != nil || u.Scheme != "com.butterflymx.oauth" || u.Host != "oauth" {
			t.Fatalf("location = %q", loc)
		}
		code = u.Query().Get("code")
		want := f.Response.Headers["location"]
		wantCode := regexp.MustCompile(`code=[^&]+`).FindString(want)
		if strings.Replace(loc, "code="+code, wantCode, 1) != want {
			t.Errorf("location = %q, fixture %q", loc, want)
		}
	})
	r.step("accounts/post-oauth-token-200", sendOpts{merge: true, form: url.Values{"code": {code}}}, func(f fixture, got reply) {
		body := jsonOf(t, got)
		if body["scope"] != "openid profile" || body["expires_in"] != float64(86400) || body["token_type"] != "Bearer" {
			t.Errorf("token response = %v", body)
		}
		r.ids["FAKE_ACCESS_TOKEN"] = body["access_token"].(string)
	})
	r.step("accounts/get-api-mobile-regions-200", sendOpts{token: r.ids["FAKE_ACCESS_TOKEN"]}, func(f fixture, got reply) {
		var want, have any
		_ = json.Unmarshal(f.Response.Body, &want)
		_ = json.Unmarshal(got.Body, &have)
		if !reflect.DeepEqual(want, have) {
			t.Errorf("regions = %s", got.Body)
		}
	})
}

// mfaReplay holds the page tokens the SMS and email conformance replays carry
// from one step to the next, like the app does.
type mfaReplay struct {
	meta  string
	forms map[string]string // form action -> authenticity token
}

func (m *mfaReplay) take(t *testing.T, got reply) { m.meta, m.forms = pageTokens(t, got.Body) }

// post options for the plain picker and resend form posts (no X-CSRF-Token).
func (m *mfaReplay) choose(action string) sendOpts {
	return sendOpts{merge: true, form: url.Values{"authenticity_token": {m.forms[action]}}}
}

// verify options for the verify form: form token in the body, meta token in
// the header.
func (m *mfaReplay) verify(code string) sendOpts {
	return sendOpts{
		merge: true, form: url.Values{"authenticity_token": {m.forms[pathVerify]}, "code": {code}},
		header: map[string]string{"X-CSRF-Token": m.meta},
	}
}

// loginToTwoFactor replays the authorize redirect, the login page and the
// password step up to (and including) fixture loginFixture.
func loginToTwoFactor(t *testing.T, r *replay, loginFixture string) {
	var meta, form string
	r.step("accounts/get-oauth-authorize-302-to-login", sendOpts{}, nil)
	r.step("accounts/get-login-new-200", sendOpts{}, func(f fixture, got reply) { meta, form = csrfTokens(t, got.Body) })
	r.step(loginFixture, sendOpts{
		merge: true, form: url.Values{"authenticity_token": {form}, "login[password]": {DefaultPassword}},
		header: map[string]string{"X-CSRF-Token": meta},
	}, func(f fixture, got reply) {
		want, _ := url.Parse(f.Response.Headers["location"])
		have, _ := url.Parse(got.Header.Get("Location"))
		if want.RequestURI() != have.RequestURI() {
			t.Errorf("location = %s, want path %s", have.RequestURI(), want.RequestURI())
		}
	})
}

// sameTurboStream expects the exact turbo-stream of the fixture: with the
// capture's own authorize query the location is reproduced byte for byte.
func sameTurboStream(t *testing.T) func(f fixture, got reply) {
	return func(f fixture, got reply) {
		var want string
		if err := json.Unmarshal(f.Response.Body, &want); err != nil {
			t.Fatal(err)
		}
		if string(got.Body) != want {
			t.Errorf("turbo-stream\n got: %s\nwant: %s", got.Body, want)
		}
	}
}

// TestConformanceAccountsSMS replays the SMS exchanges as one session. The
// resident's last method must be sms for the login to redirect to it
// (post-login-303-to-sms), which WithLastMFAMethod stands in for (in the
// capture it was an earlier SMS login). The challenge page GET sends the
// first code (the default WithMFASendOnGET(true)), so the wrong-code and
// success steps need no picker step.
func TestConformanceAccountsSMS(t *testing.T) {
	s := newTestServer(t, WithLastMFAMethod("sms"))
	r := &replay{t: t, s: s, c: newClient(), ids: map[string]string{}, tags: map[string]string{}}
	var m mfaReplay

	loginToTwoFactor(t, r, "accounts/post-login-303-to-sms")
	r.step("accounts/get-two-factor-new-200-sms", sendOpts{}, func(f fixture, got reply) { m.take(t, got) })
	if len(s.MFADeliveries()) != 1 {
		t.Fatalf("deliveries after the challenge GET = %+v", s.MFADeliveries())
	}
	bad := "000000"
	if s.LastMFACode("sms") == bad {
		bad = "999999"
	}
	r.step("accounts/post-two-factor-422-wrong-code-sms", m.verify(bad), func(f fixture, got reply) { m.take(t, got) })
	// The resend form posts only its own token, with the capture's browser Accept.
	r.step("accounts/post-two-factor-resend-sms-200", m.choose(pathSMS), func(f fixture, got reply) { m.take(t, got) })
	if len(s.MFADeliveries()) != 2 {
		t.Fatalf("deliveries after the resend = %+v", s.MFADeliveries())
	}
	r.step("accounts/post-two-factor-200-turbo-stream-sms", m.verify(s.LastMFACode("sms")), sameTurboStream(t))
}

// TestConformanceAccountsEmail replays the picker and the email exchanges.
// The first login redirects to the authenticator page (the default last
// method, post-login-303); the picker then chooses sms and email, as the
// capture did (post-two-factor-new-200-sms is the picker's sms choice).
func TestConformanceAccountsEmail(t *testing.T) {
	s := newTestServer(t)
	r := &replay{t: t, s: s, c: newClient(), ids: map[string]string{}, tags: map[string]string{}}
	var m mfaReplay

	loginToTwoFactor(t, r, "accounts/post-login-303")
	r.step("accounts/get-two-factor-new-200", sendOpts{}, nil)
	if len(s.MFADeliveries()) != 0 {
		t.Fatalf("the authenticator page sent a code: %+v", s.MFADeliveries())
	}
	r.step("accounts/get-two-factor-methods-200", sendOpts{}, func(f fixture, got reply) { m.take(t, got) })
	picker := m
	r.step("accounts/post-two-factor-new-200-sms", picker.choose(pathSMS), nil)
	r.step("accounts/post-two-factor-new-200-email", picker.choose(pathEmail), func(f fixture, got reply) { m.take(t, got) })
	if dl := s.MFADeliveries(); len(dl) != 2 || dl[0].Method != "sms" || dl[1].Method != "email" {
		t.Fatalf("deliveries after the picker = %+v", dl)
	}
	bad := "000000"
	if s.LastMFACode("email") == bad {
		bad = "999999"
	}
	r.step("accounts/post-two-factor-422-wrong-code-email", m.verify(bad), func(f fixture, got reply) { m.take(t, got) })
	r.step("accounts/post-two-factor-200-turbo-stream-email", m.verify(s.LastMFACode("email")), sameTurboStream(t))
}

func TestConformanceAPI(t *testing.T) {
	s := newTestServer(t, WithClock(func() time.Time { return fixedNow }))
	oauth := login(t, s).Access
	r := &replay{t: t, s: s, c: newClient(), ids: map[string]string{}, tags: map[string]string{}}
	var tok string

	// denizen login: the fixture carries the placeholder token.
	f := loadFixture(t, "denizen/post-login-200")
	body := strings.ReplaceAll(f.reqJSON(), "FAKE_ACCESS_TOKEN", oauth)
	r.step("denizen/post-login-200", sendOpts{body: &body}, func(f fixture, got reply) { tok = jsonOf(t, got)["token"].(string) })
	if tok == "" {
		t.Fatal("no API token")
	}

	// GraphQL: the recorded documents and variables, unchanged.
	for _, op := range []string{
		"CurrentUser", "Tenants", "Tenant", "TenantAccessPoints", "TenantDoorReleases", "TenantCalls", "TenantMessages",
		"TenantRemoteLocks", "TenantSmartLocks", "TenantLPRSettings", "GetBLECredentials",
	} {
		r.step("graphql/"+op, sendOpts{token: tok}, nil)
	}
	r.step("unlock/post-access-point-200", sendOpts{token: tok}, nil)

	// REST, in the order of the capture. IDs the capture generated are mapped
	// to the IDs the fake generates.
	capture := func(fixtureID string, path ...any) func(fixture, reply) {
		return func(_ fixture, got reply) { r.ids[fixtureID] = dig(t, jsonOf(t, got), path...).(string) }
	}
	sameAttrs := func(f fixture, got reply) {
		var want map[string]any
		_ = json.Unmarshal(f.Response.Body, &want)
		have := jsonOf(t, got)
		if !reflect.DeepEqual(dig(t, want, "data", "attributes"), dig(t, have, "data", "attributes")) {
			t.Errorf("attributes\n got: %v\nwant: %v", dig(t, have, "data", "attributes"), dig(t, want, "data", "attributes"))
		}
	}
	both := func(fs ...func(fixture, reply)) func(fixture, reply) {
		return func(f fixture, got reply) {
			for _, fn := range fs {
				fn(f, got)
			}
		}
	}
	o := sendOpts{token: tok}
	with := func(inm string) sendOpts { return sendOpts{token: tok, inm: r.tags[inm]} }

	r.step("rest/get-access-codes-active-200-baseline", o, nil)
	r.step("rest/get-keychains-custom-200-existing", o, nil) // a seeded pass has the fixture's ID
	r.step("rest/get-access-codes-active-304", with("rest/get-access-codes-active-200-baseline"), nil)
	r.step("rest/get-access-codes-expired-200", o, nil)

	r.step("rest/post-keychains-custom-201", o, both(capture("85303961", "data", "id"), sameAttrs))
	r.step("rest/get-keychains-custom-200-created", o, nil)
	r.step("rest/get-access-codes-active-200-after-custom-create", o, nil)
	r.step("rest/post-keychains-virtual-keys-201", o, capture("12915969", "data", 0, "id"))
	r.step("rest/get-keychains-custom-200-second-key-added", o, nil)
	r.step("rest/get-keychains-custom-200-second-key-sent", o, nil)
	r.step("rest/delete-keychains-virtual-keys-204", o, nil)
	r.step("rest/get-keychains-custom-200-key-revoked", o, nil)

	r.step("rest/post-keychains-recurring-201", o, both(capture("35154212", "data", "id"), sameAttrs))
	r.step("rest/get-keychains-recurring-200", o, nil)
	r.step("rest/get-keychains-304", with("rest/get-keychains-recurring-200"), nil)
	r.step("rest/get-access-codes-active-200-after-recurring-create", o, nil)
	t.Run("(not a fixture) delete the recurring pass", func(t *testing.T) {
		wantStatus(t, api(t, s, tok, "DELETE", "/v3/keychains/"+r.ids["35154212"], nil), 204)
	})
	r.step("rest/get-access-codes-active-200-after-recurring-delete", o, nil)

	r.step("rest/post-keychains-delivery-pass-201", o, both(capture("75337466", "data", "id"), sameAttrs,
		func(_ fixture, got reply) {
			r.ids["55244830"] = dig(t, jsonOf(t, got), "included", 0, "id").(string)
		}))
	r.step("rest/get-access-codes-active-200-after-delivery-pass-create", o, nil)
	r.step("rest/patch-keychains-delivery-pass-204-rename", o, nil)
	r.step("rest/get-access-codes-active-200-after-delivery-pass-rename", o, nil)
	r.step("rest/patch-keychains-delivery-pass-204-extend", o, nil)
	r.step("rest/get-access-codes-active-200-after-delivery-pass-extend", o, nil)
	r.step("rest/delete-keychains-delivery-pass-204", o, nil)
	r.step("rest/delete-keychains-204", o, nil)

	// /mobile/v4 push devices (form encoded).
	r.step("rest/post-mobile-users-devices-200", o, capture("65794426", "data", "id"))
	r.step("rest/patch-mobile-users-devices-200", o, nil)
	r.step("rest/delete-mobile-users-devices-204", o, nil)

	r.step("denizen/delete-logout-200", o, nil)
}

// TestConformanceCoversEveryFixture fails when a fixture in the replayed
// directories is neither replayed nor listed as skipped.
func TestConformanceCoversEveryFixture(t *testing.T) {
	replayed := map[string]bool{}
	src, err := os.ReadFile("conformance_test.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`"((?:rest|graphql|denizen|unlock|accounts)/[A-Za-z0-9._-]+)"`).FindAllStringSubmatch(string(src), -1) {
		replayed[m[1]] = true
	}
	for _, op := range []string{"CurrentUser", "Tenants", "Tenant", "TenantAccessPoints", "TenantDoorReleases", "TenantCalls", "TenantMessages",
		"TenantRemoteLocks", "TenantSmartLocks", "TenantLPRSettings", "GetBLECredentials"} {
		replayed["graphql/"+op] = true
	}
	for _, dir := range []string{"rest", "graphql", "denizen", "unlock", "accounts"} {
		files, err := filepath.Glob(filepath.Join("..", "testdata", dir, "*.json"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no fixtures in %s", dir)
		}
		for _, f := range files {
			name := dir + "/" + strings.TrimSuffix(filepath.Base(f), ".json")
			if !replayed[name] {
				t.Errorf("fixture %s is not replayed by the conformance tests", name)
			}
		}
	}
}
