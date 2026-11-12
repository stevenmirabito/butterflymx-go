package butterflymxtest

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

var (
	reForm     = regexp.MustCompile(`(?s)<form[^>]*\baction="([^"]*)"[^>]*>(.*?)</form>`)
	reFormAuth = regexp.MustCompile(`name="authenticity_token" type="hidden" value="([^"]*)"`)
)

// pageTokens returns the page's meta token and the token of every form by its
// (unescaped) action.
func pageTokens(t testing.TB, body []byte) (meta string, forms map[string]string) {
	t.Helper()
	m := reMeta.FindSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf-token meta tag:\n%s", body)
	}
	forms = map[string]string{}
	for _, f := range reForm.FindAllStringSubmatch(string(body), -1) {
		if tk := reFormAuth.FindStringSubmatch(f[2]); tk != nil {
			forms[html.UnescapeString(f[1])] = tk[1]
		}
	}
	return string(m[1]), forms
}

// mfaFlow drives the 2FA endpoints like the app does, with plain net/http.
type mfaFlow struct {
	t *testing.T
	s *Server
	c *http.Client
}

func newMFAFlow(t *testing.T, opts ...Option) *mfaFlow {
	return &mfaFlow{t: t, s: newTestServer(t, opts...), c: newClient()}
}

// login does authorize, the login page and POST /login, and returns the 303
// Location.
func (f *mfaFlow) login() string {
	f.t.Helper()
	do(f.t, f.c, "GET", authorizeURL(f.s.URL(), newPKCE(), "st", true), nil, nil)
	r := do(f.t, f.c, "GET", f.s.URL()+"/login/new", nil, nil)
	meta, form := csrfTokens(f.t, r.Body)
	r = do(f.t, f.c, "POST", f.s.URL()+"/login", formBody("authenticity_token", form, "login[email]", DefaultEmail,
		"login[password]", DefaultPassword, "commit", "Sign in with email"), formHdr(meta))
	wantStatus(f.t, r, 303)
	return r.Header.Get("Location")
}

func (f *mfaFlow) get(u string) reply {
	f.t.Helper()
	return do(f.t, f.c, "GET", u, nil, map[string]string{"Accept": "text/vnd.turbo-stream.html, text/html, application/xhtml+xml"})
}

// postForm is the plain form post of the picker and the resend form: no
// X-CSRF-Token header, a browser-style Accept.
func (f *mfaFlow) postForm(action, token string, kv ...string) reply {
	f.t.Helper()
	return do(f.t, f.c, "POST", f.s.URL()+action, formBody(append([]string{"authenticity_token", token}, kv...)...),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"})
}

// verify posts the code like the app: form token in the body, meta token in
// the header.
func (f *mfaFlow) verify(method, code, meta, form string) reply {
	f.t.Helper()
	return do(f.t, f.c, "POST", f.s.URL()+"/sessions/two_factor_authentication",
		formBody("authenticity_token", form, "type", method, "code", code, "commit", "Use code"), formHdr(meta))
}

func wantTurbo(t *testing.T, r reply) {
	t.Helper()
	wantStatus(t, r, 200)
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "text/vnd.turbo-stream.html") || !strings.Contains(string(r.Body), `action="redirect_to"`) {
		t.Fatalf("not a redirect_to turbo-stream: %s %s", r.Header.Get("Content-Type"), r.Body)
	}
}

func wantFailedPage(t *testing.T, r reply, method string) {
	t.Helper()
	wantStatus(t, r, 422)
	for _, want := range []string{"Two factor authentication failed.", "Invalid code, please try again or request a new code.",
		`name="type" type="hidden" value="` + method + `"`} {
		if !strings.Contains(string(r.Body), want) {
			t.Errorf("422 page lacks %q:\n%s", want, r.Body)
		}
	}
}

func lastRedirectMethod(t *testing.T, loc string) string {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil || u.Path != "/sessions/two_factor_authentication/new" {
		t.Fatalf("2FA location = %q", loc)
	}
	return u.Query().Get("type")
}

const (
	pathVerify = "/sessions/two_factor_authentication"
	pathSMS    = "/sessions/two_factor_authentication/new?type=sms"
	pathEmail  = "/sessions/two_factor_authentication/new?type=email"
	pathApp    = "/sessions/two_factor_authentication/new?type=authenticator_app"
)

func TestSMSLoginWithWrongCodeAndResend(t *testing.T) {
	now := fixedNow
	f := newMFAFlow(t, WithLastMFAMethod("sms"), WithClock(func() time.Time { return now }))
	loc := f.login()
	if m := lastRedirectMethod(t, loc); m != "sms" {
		t.Fatalf("redirect type = %q, want sms", m)
	}

	r := f.get(loc)
	wantStatus(t, r, 200)
	body := string(r.Body)
	for _, want := range []string{
		"<title>\n   ButterflyMX - Verify with text message\n  </title>",
		"A 6-digit code has been sent to your phone number ******0100",
		`<form accept-charset="UTF-8" action="/sessions/two_factor_authentication" method="post">`,
		`<form action="/sessions/two_factor_authentication/new?type=sms" method="post">`,
		"Resend code", `name="context" type="hidden" value="resend"`,
		`<a href="/sessions/two_factor_authentication">`, "Verify another way",
		`autocomplete="one-time-code"`, `name="commit" type="submit" value="Use code"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("SMS page lacks %q", want)
		}
	}
	if strings.Contains(body, "Two factor authentication failed.") || strings.Contains(body, "classs=") {
		t.Error("fresh challenge page must have no flash message")
	}
	meta, forms := pageTokens(t, r.Body)
	if len(forms) != 2 || forms[pathVerify] == "" || forms[pathSMS] == "" {
		t.Fatalf("forms = %v", forms)
	}
	if meta == forms[pathVerify] || meta == forms[pathSMS] || forms[pathVerify] == forms[pathSMS] {
		t.Error("meta, verify and resend tokens must all differ")
	}

	dl := f.s.MFADeliveries()
	if len(dl) != 1 || dl[0].Method != "sms" || dl[0].Destination != "******0100" || dl[0].Resend || dl[0].Trigger != "challenge-get" ||
		!dl[0].At.Equal(fixedNow) || !regexp.MustCompile(`^\d{6}$`).MatchString(dl[0].Code) {
		t.Fatalf("deliveries = %+v", dl)
	}
	first := dl[0].Code

	// A wrong code: 422, the page again with fresh tokens.
	wrong := "000000"
	if wrong == first {
		wrong = "111111"
	}
	r = f.verify("sms", wrong, meta, forms[pathVerify])
	wantFailedPage(t, r, "sms")
	meta2, forms2 := pageTokens(t, r.Body)
	if meta2 == meta || forms2[pathVerify] == forms[pathVerify] || forms2[pathSMS] == forms[pathSMS] {
		t.Error("expected fresh tokens on the 422 page")
	}

	// Resend: the notice, a second code, and both codes stay valid.
	r = f.postForm(pathSMS, forms2[pathSMS], "context", "resend")
	wantStatus(t, r, 200)
	if !strings.Contains(string(r.Body), "A code has been sent to your phone number.") {
		t.Errorf("resend page lacks the notice:\n%s", r.Body)
	}
	meta3, forms3 := pageTokens(t, r.Body)
	dl = f.s.MFADeliveries()
	if len(dl) != 2 || !dl[1].Resend || dl[1].Trigger != "resend" || dl[1].Code == first || f.s.LastMFACode("sms") != dl[1].Code {
		t.Fatalf("deliveries = %+v", dl)
	}
	if f.s.LastMFACode("email") != "" {
		t.Error("no email was sent")
	}

	// The first code still works (it is the one we verify with).
	wantTurbo(t, f.verify("sms", first, meta3, forms3[pathVerify]))
	// ... and so does the second, in a new login of the same account.
	if f.s.lastMFA != "sms" {
		t.Errorf("last method = %q", f.s.lastMFA)
	}
}

func TestAllCodesOfTheSessionStayValid(t *testing.T) {
	f := newMFAFlow(t, WithLastMFAMethod("sms"))
	loc := f.login()
	r := f.get(loc)
	_, forms := pageTokens(t, r.Body)
	r = f.postForm(pathSMS, forms[pathSMS], "context", "resend")
	meta, forms := pageTokens(t, r.Body)
	dl := f.s.MFADeliveries()
	if len(dl) != 2 {
		t.Fatalf("deliveries = %+v", dl)
	}
	wantTurbo(t, f.verify("sms", dl[1].Code, meta, forms[pathVerify]))
}

func TestEmailViaPickerFromAuthenticatorDefault(t *testing.T) {
	f := newMFAFlow(t)
	loc := f.login()
	if m := lastRedirectMethod(t, loc); m != "authenticator_app" {
		t.Fatalf("redirect type = %q", m)
	}
	wantStatus(t, f.get(loc), 200)
	if len(f.s.MFADeliveries()) != 0 {
		t.Fatal("the authenticator page must not send a code")
	}

	r := f.get(f.s.URL() + pathVerify)
	wantStatus(t, r, 200)
	body := string(r.Body)
	for _, want := range []string{
		"How do you want to verify your account?", "Choose one of the following options to use a 2nd factor authentication method",
		"Receive a code from your ButterflyMX email address", "Receive a code via text on your mobile device",
		"Receive a code from an authenticator app", `href="mailto:support@butterflymx.com"`, `href="tel:8003984416"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("picker lacks %q", want)
		}
	}
	iE, iS, iA := strings.Index(body, "type=email"), strings.Index(body, "type=sms"), strings.Index(body, "type=authenticator_app")
	if 0 >= iE || iE >= iS || iS >= iA {
		t.Errorf("picker order wrong: email %d sms %d app %d", iE, iS, iA)
	}
	meta, forms := pageTokens(t, r.Body)
	if len(forms) != 3 || forms[pathEmail] == forms[pathSMS] || forms[pathSMS] == forms[pathApp] || forms[pathEmail] == forms[pathApp] || meta == forms[pathEmail] {
		t.Fatalf("picker tokens must be distinct: meta=%s forms=%v", meta, forms)
	}

	r = f.postForm(pathEmail, forms[pathEmail])
	wantStatus(t, r, 200)
	if !strings.Contains(string(r.Body), "A 6-digit code has been sent to your email") || strings.Contains(string(r.Body), "resident@example.com") {
		t.Errorf("email page:\n%s", r.Body)
	}
	if !strings.Contains(string(r.Body), "Verify with an Email") || strings.Contains(string(r.Body), "A code has been sent to your email.") {
		t.Errorf("email page heading or notice wrong:\n%s", r.Body)
	}
	dl := f.s.MFADeliveries()
	if len(dl) != 1 || dl[0].Method != "email" || dl[0].Destination != "resident@example.com" || dl[0].Trigger != "picker" || dl[0].Resend {
		t.Fatalf("deliveries = %+v", dl)
	}

	meta, forms = pageTokens(t, r.Body)
	r = f.verify("email", "123abc", meta, forms[pathVerify])
	wantFailedPage(t, r, "email")
	meta, forms = pageTokens(t, r.Body)
	wantTurbo(t, f.verify("email", f.s.LastMFACode("email"), meta, forms[pathVerify]))
}

func TestEmailResendNotice(t *testing.T) {
	f := newMFAFlow(t, WithLastMFAMethod("email"))
	r := f.get(f.login())
	_, forms := pageTokens(t, r.Body)
	r = f.postForm(pathEmail, forms[pathEmail], "context", "resend")
	wantStatus(t, r, 200)
	if !strings.Contains(string(r.Body), "A code has been sent to your email.") {
		t.Errorf("no notice:\n%s", r.Body)
	}
	if dl := f.s.MFADeliveries(); len(dl) != 2 || dl[0].Trigger != "challenge-get" || dl[1].Trigger != "resend" {
		t.Fatalf("deliveries = %+v", dl)
	}
}

func TestPickerChoosingAuthenticatorSendsNothing(t *testing.T) {
	f := newMFAFlow(t)
	f.login()
	_, forms := pageTokens(t, f.get(f.s.URL()+pathVerify).Body)
	r := f.postForm(pathApp, forms[pathApp])
	wantStatus(t, r, 200)
	if !strings.Contains(string(r.Body), "Verify with an authenticator app") || strings.Contains(string(r.Body), "Resend code") {
		t.Errorf("page:\n%s", r.Body)
	}
	if len(f.s.MFADeliveries()) != 0 {
		t.Error("nothing should be sent")
	}
	// the authenticator still works, with no code ever sent
	meta, vforms := pageTokens(t, r.Body)
	wantTurbo(t, f.verify("authenticator_app", f.s.CurrentTOTP(), meta, vforms[pathVerify]))
}

func TestUnknownMethod(t *testing.T) {
	f := newMFAFlow(t)
	f.login()
	r := f.get(f.s.URL() + "/sessions/two_factor_authentication/new?type=carrier_pigeon")
	if r.StatusCode != http.StatusNotFound || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") {
		t.Errorf("status = %d, content type %q", r.StatusCode, r.Header.Get("Content-Type"))
	}
	r = f.postForm("/sessions/two_factor_authentication/new?type=carrier_pigeon", "x")
	wantStatus(t, r, 404)
}

func TestLastUsedMethodIsRemembered(t *testing.T) {
	s := newTestServer(t)

	// Initially the authenticator app.
	f := &mfaFlow{t: t, s: s, c: newClient()}
	if m := lastRedirectMethod(t, f.login()); m != "authenticator_app" {
		t.Fatalf("first login redirects to %q", m)
	}

	// Log in via SMS (picker), verify.
	_, forms := pageTokens(t, f.get(s.URL()+pathVerify).Body)
	r := f.postForm(pathSMS, forms[pathSMS])
	meta, vf := pageTokens(t, r.Body)
	wantTurbo(t, f.verify("sms", s.LastMFACode("sms"), meta, vf[pathVerify]))

	// The next login, in a new session, goes straight to sms.
	f2 := &mfaFlow{t: t, s: s, c: newClient()}
	if m := lastRedirectMethod(t, f2.login()); m != "sms" {
		t.Fatalf("second login redirects to %q, want sms", m)
	}
	// An abandoned challenge does not change the memory, a TOTP login does.
	f3 := &mfaFlow{t: t, s: s, c: newClient()}
	loc := f3.login()
	if m := lastRedirectMethod(t, loc); m != "sms" {
		t.Fatalf("redirect = %q", m)
	}
	_, forms = pageTokens(t, f3.get(s.URL()+pathVerify).Body)
	r = f3.postForm(pathApp, forms[pathApp])
	meta, vf = pageTokens(t, r.Body)
	wantTurbo(t, f3.verify("authenticator_app", s.CurrentTOTP(), meta, vf[pathVerify]))
	if m := lastRedirectMethod(t, (&mfaFlow{t: t, s: s, c: newClient()}).login()); m != "authenticator_app" {
		t.Fatalf("redirect after TOTP login = %q", m)
	}
}

func TestWithLastMFAMethod(t *testing.T) {
	f := newMFAFlow(t, WithLastMFAMethod("email"))
	if m := lastRedirectMethod(t, f.login()); m != "email" {
		t.Fatalf("redirect = %q", m)
	}
	defer func() {
		if recover() == nil {
			t.Error("an unknown method must panic")
		}
	}()
	WithLastMFAMethod("fax")
}

func TestWrongFormTokensAreRejected(t *testing.T) {
	f := newMFAFlow(t)
	f.login()
	pickerMeta, picker := pageTokens(t, f.get(f.s.URL()+pathVerify).Body)

	// Picker: another form's token, the meta token, junk, none.
	for name, tok := range map[string]string{
		"token of another picker form": picker[pathSMS],
		"meta token":                   pickerMeta,
		"junk":                         "nope",
		"empty":                        "",
	} {
		if r := f.postForm(pathEmail, tok); r.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("picker with %s: status = %d, want 422", name, r.StatusCode)
		}
	}
	if len(f.s.MFADeliveries()) != 0 {
		t.Fatal("rejected posts must not send codes")
	}
	// The picker needs no X-CSRF-Token (postForm sends none).
	r := f.postForm(pathSMS, picker[pathSMS])
	wantStatus(t, r, 200)
	meta, forms := pageTokens(t, r.Body)

	// Picker and resend tokens are not accepted for the verify form, and vice versa.
	code := f.s.LastMFACode("sms")
	if r := f.verify("sms", code, meta, forms[pathSMS]); r.StatusCode != http.StatusUnprocessableEntity || strings.Contains(string(r.Body), "Invalid code") {
		t.Errorf("verify with the resend token: status = %d, body:\n%s", r.StatusCode, r.Body)
	}
	if r := f.verify("sms", code, meta, picker[pathSMS]); r.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("verify with a picker token: status = %d", r.StatusCode)
	}
	if r := f.verify("sms", code, meta, ""); r.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("verify without a form token: status = %d", r.StatusCode)
	}
	if r := f.postForm(pathSMS, forms[pathVerify], "context", "resend"); r.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("resend with the verify token: status = %d", r.StatusCode)
	}
	if r := f.postForm(pathEmail, forms[pathSMS], "context", "resend"); r.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("resend for email with the sms token: status = %d", r.StatusCode)
	}
	if r := f.postForm(pathSMS, "stale-token", "context", "resend"); r.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("resend with a stale token: status = %d", r.StatusCode)
	}
	if got := len(f.s.MFADeliveries()); got != 1 {
		t.Errorf("deliveries = %d, want 1", got)
	}

	// Verify requires the meta token in the header, and rejects a form token there.
	post := func(hdr map[string]string) reply {
		return do(t, f.c, "POST", f.s.URL()+pathVerify,
			formBody("authenticity_token", forms[pathVerify], "type", "sms", "code", code, "commit", "Use code"), hdr)
	}
	noHdr := formHdr("")
	delete(noHdr, "X-CSRF-Token")
	if r := post(noHdr); r.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("verify without X-CSRF-Token: status = %d", r.StatusCode)
	}
	if r := post(formHdr(forms[pathVerify])); r.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("verify with a form token in X-CSRF-Token: status = %d", r.StatusCode)
	}
	// An old (still issued) meta token is fine, like in Rails.
	wantTurbo(t, post(formHdr(meta)))

	// The 422 for a bad token has the login page's shape.
	if r := f.postForm(pathEmail, "junk"); !strings.Contains(string(r.Body), "Invalid authenticity token") {
		t.Errorf("CSRF failure body: %s", r.Body)
	}
}

func TestPostsWithoutLoginAreRejected(t *testing.T) {
	s := newTestServer(t)
	f := &mfaFlow{t: t, s: s, c: newClient()}
	r := f.postForm(pathSMS, "x")
	wantStatus(t, r, 422)
	if len(s.MFADeliveries()) != 0 {
		t.Error("nothing should be sent")
	}
	r = f.get(s.URL() + pathVerify)
	wantStatus(t, r, 302)
	r = f.get(s.URL() + pathSMS)
	wantStatus(t, r, 302)
}

func TestMFACodeExpiry(t *testing.T) {
	now := fixedNow
	f := newMFAFlow(t, WithLastMFAMethod("sms"), WithClock(func() time.Time { return now }))
	r := f.get(f.login())
	meta, forms := pageTokens(t, r.Body)
	old := f.s.LastMFACode("sms")

	now = now.Add(10*time.Minute - time.Second)
	r2 := f.verify("sms", old, meta, forms[pathVerify])
	wantTurbo(t, r2) // still valid at 9:59

	// Expired after 10 minutes; a code sent later is valid.
	f2 := newMFAFlow(t, WithLastMFAMethod("sms"), WithClock(func() time.Time { return now }))
	r = f2.get(f2.login())
	meta, forms = pageTokens(t, r.Body)
	first := f2.s.LastMFACode("sms")
	now = now.Add(10 * time.Minute)
	wantFailedPage(t, f2.verify("sms", first, meta, forms[pathVerify]), "sms")
	_, forms = pageTokens(t, f2.get(f2.s.URL()+pathVerify).Body)
	r = f2.postForm(pathSMS, forms[pathSMS])
	meta, forms = pageTokens(t, r.Body)
	second := f2.s.LastMFACode("sms")
	if second == first {
		t.Fatal("codes must differ")
	}
	dl := f2.s.MFADeliveries()
	if !dl[1].At.Equal(now.Truncate(time.Second)) {
		t.Errorf("delivery time = %v, want %v", dl[1].At, now)
	}
	wantFailedPage(t, f2.verify("sms", first, meta, forms[pathVerify]), "sms")
	_, forms = pageTokens(t, f2.get(f2.s.URL()+pathVerify).Body)
	r = f2.postForm(pathSMS, forms[pathSMS])
	meta, forms = pageTokens(t, r.Body)
	wantTurbo(t, f2.verify("sms", f2.s.LastMFACode("sms"), meta, forms[pathVerify]))
}

func TestMFASendOnGETOption(t *testing.T) {
	// Default: the first GET sends, later GETs do not.
	f := newMFAFlow(t, WithLastMFAMethod("sms"))
	loc := f.login()
	f.get(loc)
	f.get(loc)
	if dl := f.s.MFADeliveries(); len(dl) != 1 || dl[0].Trigger != "challenge-get" {
		t.Fatalf("deliveries = %+v", dl)
	}
	// A new login session sends again.
	f.c = newClient()
	f.get(f.login())
	if got := len(f.s.MFADeliveries()); got != 2 {
		t.Fatalf("deliveries = %d, want 2", got)
	}

	// Off: GET never sends; the picker does; a GET after the picker does not either.
	g := newMFAFlow(t, WithLastMFAMethod("sms"), WithMFASendOnGET(false))
	loc = g.login()
	r := g.get(loc)
	wantStatus(t, r, 200)
	if !strings.Contains(string(r.Body), "A 6-digit code has been sent to your phone number ******0100") {
		t.Error("the page still says the code has been sent")
	}
	if len(g.s.MFADeliveries()) != 0 || g.s.LastMFACode("sms") != "" {
		t.Fatalf("deliveries = %+v", g.s.MFADeliveries())
	}
	meta, forms := pageTokens(t, r.Body)
	// No code was ever sent, so no code verifies.
	wantFailedPage(t, g.verify("sms", "000000", meta, forms[pathVerify]), "sms")
	r = g.get(loc)
	_, forms = pageTokens(t, r.Body)
	r = g.postForm(pathSMS, forms[pathSMS], "context", "resend")
	if dl := g.s.MFADeliveries(); len(dl) != 1 || dl[0].Trigger != "resend" {
		t.Fatalf("deliveries = %+v", dl)
	}
	meta, forms = pageTokens(t, r.Body)
	wantTurbo(t, g.verify("sms", g.s.LastMFACode("sms"), meta, forms[pathVerify]))
}

func TestMFACodesAreSixDigits(t *testing.T) {
	f := newMFAFlow(t, WithLastMFAMethod("sms"))
	r := f.get(f.login())
	_, forms := pageTokens(t, r.Body)
	seen := map[string]bool{}
	re := regexp.MustCompile(`^\d{6}$`)
	for range 40 {
		r = f.postForm(pathSMS, forms[pathSMS], "context", "resend")
		_, forms = pageTokens(t, r.Body)
	}
	for _, d := range f.s.MFADeliveries() {
		if !re.MatchString(d.Code) || seen[d.Code] {
			t.Errorf("bad or duplicate code %q", d.Code)
		}
		seen[d.Code] = true
	}
}

func TestMFARedactsCodesInRequestLog(t *testing.T) {
	f := newMFAFlow(t, WithLastMFAMethod("sms"))
	r := f.get(f.login())
	meta, forms := pageTokens(t, r.Body)
	code := f.s.LastMFACode("sms")
	wantTurbo(t, f.verify("sms", code, meta, forms[pathVerify]))
	for _, rq := range f.s.Requests() {
		if strings.Contains(rq.Body, code) || strings.Contains(rq.Body, forms[pathVerify]) {
			t.Fatalf("request log leaks a secret: %+v", rq)
		}
	}
}
