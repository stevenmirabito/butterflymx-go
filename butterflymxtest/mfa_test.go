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

const (
	pathVerify = "/login/two_factor_authentication"
	pathSMS    = "/login/two_factor_authentication/new?type=sms"
	pathEmail  = "/login/two_factor_authentication/new?type=email"
	pathApp    = "/login/two_factor_authentication/new?type=authenticator_app"
)

// pickerLinks returns the picker's links by method type (unescaped hrefs).
func pickerLinks(t testing.TB, body []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, m := range reHref.FindAllSubmatch(body, -1) {
		l := html.UnescapeString(string(m[1]))
		u, err := url.Parse(l)
		if err != nil || u.Path != "/login/two_factor_authentication/new" {
			continue
		}
		out[u.Query().Get("type")] = l
	}
	return out
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

// login does authorize, the login page and POST /login, and returns the 302
// Location.
func (f *mfaFlow) login() string {
	f.t.Helper()
	do(f.t, f.c, "GET", authorizeURL(f.s.URL(), newPKCE(), "st", true), nil, nil)
	r := do(f.t, f.c, "GET", f.s.URL()+"/login/new", nil, nil)
	r = do(f.t, f.c, "POST", f.s.URL()+"/login", loginBody(csrfToken(f.t, r.Body), DefaultEmail, DefaultPassword), formHdr())
	wantStatus(f.t, r, 302)
	return r.Header.Get("Location")
}

// get requests a path or URL.
func (f *mfaFlow) get(u string) reply {
	f.t.Helper()
	if strings.HasPrefix(u, "/") {
		u = f.s.URL() + u
	}
	return do(f.t, f.c, "GET", u, nil, map[string]string{"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"})
}

// postForm is a plain form post, as the app makes it for every form.
func (f *mfaFlow) postForm(action, token string, kv ...string) reply {
	f.t.Helper()
	return do(f.t, f.c, "POST", f.s.URL()+action, formBody(append([]string{"_csrf_token", token}, kv...)...), formHdr())
}

func (f *mfaFlow) verify(method, code, token string) reply {
	f.t.Helper()
	return f.postForm(pathVerify, token, "type", method, "code", code)
}

// resend posts the resend form and follows the redirect back to the
// challenge page, returning that page.
func (f *mfaFlow) resend(path, token string) reply {
	f.t.Helper()
	r := f.postForm(path, token, "context", "resend")
	wantStatus(f.t, r, 302)
	if got := r.Header.Get("Location"); got != path {
		f.t.Fatalf("resend location = %q, want %q", got, path)
	}
	return f.get(r.Header.Get("Location"))
}

// wantSuccess checks the redirect back to the authorize endpoint.
func wantSuccess(t *testing.T, r reply) {
	t.Helper()
	wantStatus(t, r, 302)
	if loc := r.Header.Get("Location"); !strings.HasPrefix(loc, "/oauth/authorize?") || strings.Contains(loc, "prompt") {
		t.Fatalf("success location = %q", loc)
	}
}

// wantWrongCode checks the 200 re-render of the challenge page with the error.
func wantWrongCode(t *testing.T, r reply, method string) {
	t.Helper()
	wantStatus(t, r, 200)
	for _, want := range []string{"Invalid verification code", `name="type" value="` + method + `"`, `action="/login/two_factor_authentication"`} {
		if !strings.Contains(string(r.Body), want) {
			t.Errorf("wrong-code page lacks %q:\n%s", want, r.Body)
		}
	}
}

func redirectMethod(t *testing.T, loc string) string {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil || u.Path != "/login/two_factor_authentication/new" {
		t.Fatalf("2FA location = %q", loc)
	}
	return u.Query().Get("type")
}

func TestSMSLoginWithWrongCodeAndResend(t *testing.T) {
	now := fixedNow
	f := newMFAFlow(t, WithLastMFAMethod("sms"), WithClock(func() time.Time { return now }))
	loc := f.login()
	if m := redirectMethod(t, loc); m != "sms" {
		t.Fatalf("redirect type = %q, want sms", m)
	}

	r := f.get(loc)
	wantStatus(t, r, 200)
	body := string(r.Body)
	for _, want := range []string{
		"<title>ButterflyMX - Verify with text message</title>",
		"A 6-digit code has been sent to your phone number ******0100",
		`<form action="/login/two_factor_authentication" method="post">`,
		`<form method="post" action="/login/two_factor_authentication/new?type=sms">`,
		"Resend code", `name="context" value="resend"`,
		`<a href="/login/two_factor_authentication">Verify another way</a>`,
		`autocomplete="one-time-code"`, `value="Use code"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("SMS page lacks %q", want)
		}
	}
	if strings.Contains(body, "Invalid verification code") || strings.Contains(body, "has been sent to your phone number.") {
		t.Error("fresh challenge page must have no message")
	}
	tok := csrfToken(t, r.Body)
	if n := strings.Count(body, `name="_csrf_token" value="`+tok+`"`); n != 2 {
		t.Errorf("the session token appears in %d forms, want 2", n)
	}

	dl := f.s.MFADeliveries()
	if len(dl) != 1 || dl[0].Method != "sms" || dl[0].Destination != "******0100" || dl[0].Resend || dl[0].Trigger != "challenge-get" ||
		!dl[0].At.Equal(fixedNow) || !regexp.MustCompile(`^\d{6}$`).MatchString(dl[0].Code) {
		t.Fatalf("deliveries = %+v", dl)
	}
	first := dl[0].Code

	// A wrong code: 200, the page again with the error.
	wrong := "000000"
	if wrong == first {
		wrong = "111111"
	}
	wantWrongCode(t, f.verify("sms", wrong, tok), "sms")

	// Resend: a redirect back to the page, which shows the notice once; a
	// second code, and both stay valid.
	r = f.resend(pathSMS, tok)
	wantStatus(t, r, 200)
	if !strings.Contains(string(r.Body), "A code has been sent to your phone number.") {
		t.Errorf("resend page lacks the notice:\n%s", r.Body)
	}
	if again := f.get(pathSMS); strings.Contains(string(again.Body), "A code has been sent to your phone number.") {
		t.Error("the notice must be shown once")
	}
	dl = f.s.MFADeliveries()
	if len(dl) != 2 || !dl[1].Resend || dl[1].Trigger != "resend" || dl[1].Code == first || f.s.LastMFACode("sms") != dl[1].Code {
		t.Fatalf("deliveries = %+v", dl)
	}
	if f.s.LastMFACode("email") != "" {
		t.Error("no email was sent")
	}

	// The first code still works.
	wantSuccess(t, f.verify("sms", first, tok))
	if f.s.lastMFA != "sms" {
		t.Errorf("last method = %q", f.s.lastMFA)
	}
}

func TestAllCodesOfTheSessionStayValid(t *testing.T) {
	f := newMFAFlow(t, WithLastMFAMethod("sms"))
	r := f.get(f.login())
	tok := csrfToken(t, r.Body)
	f.resend(pathSMS, tok)
	dl := f.s.MFADeliveries()
	if len(dl) != 2 {
		t.Fatalf("deliveries = %+v", dl)
	}
	wantSuccess(t, f.verify("sms", dl[1].Code, tok))
}

func TestEmailViaPickerFromAuthenticatorDefault(t *testing.T) {
	f := newMFAFlow(t)
	loc := f.login()
	if m := redirectMethod(t, loc); m != "authenticator_app" {
		t.Fatalf("redirect type = %q", m)
	}
	wantStatus(t, f.get(loc), 200)
	if len(f.s.MFADeliveries()) != 0 {
		t.Fatal("the authenticator page must not send a code")
	}

	r := f.get(pathVerify)
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
	if strings.Contains(body, "<form") {
		t.Error("the picker is links, not forms")
	}
	iE, iS, iA := strings.Index(body, "type=email"), strings.Index(body, "type=sms"), strings.Index(body, "type=authenticator_app")
	if 0 >= iE || iE >= iS || iS >= iA {
		t.Errorf("picker order wrong: email %d sms %d app %d", iE, iS, iA)
	}
	links := pickerLinks(t, r.Body)
	if len(links) != 3 || !strings.Contains(links["email"], "account_id=") {
		t.Fatalf("picker links = %v", links)
	}

	// Following the link chooses the method and sends the code.
	r = f.get(links["email"])
	wantStatus(t, r, 200)
	if !strings.Contains(string(r.Body), "A 6-digit code has been sent to your email") || strings.Contains(string(r.Body), "resident@example.com") {
		t.Errorf("email page:\n%s", r.Body)
	}
	if !strings.Contains(string(r.Body), "Verify with an Email") {
		t.Errorf("email page heading wrong:\n%s", r.Body)
	}
	dl := f.s.MFADeliveries()
	if len(dl) != 1 || dl[0].Method != "email" || dl[0].Destination != "resident@example.com" || dl[0].Trigger != "picker" || dl[0].Resend {
		t.Fatalf("deliveries = %+v", dl)
	}

	tok := csrfToken(t, r.Body)
	wantWrongCode(t, f.verify("email", "123abc", tok), "email")
	wantSuccess(t, f.verify("email", f.s.LastMFACode("email"), tok))
}

func TestChoosingTheCurrentMethodAgainResends(t *testing.T) {
	f := newMFAFlow(t, WithLastMFAMethod("sms"))
	f.get(f.login())
	links := pickerLinks(t, f.get(pathVerify).Body)
	f.get(links["sms"])
	if dl := f.s.MFADeliveries(); len(dl) != 2 || dl[0].Trigger != "challenge-get" || dl[1].Trigger != "picker" {
		t.Fatalf("deliveries = %+v", dl)
	}
}

func TestEmailResendNotice(t *testing.T) {
	f := newMFAFlow(t, WithLastMFAMethod("email"))
	r := f.get(f.login())
	r = f.resend(pathEmail, csrfToken(t, r.Body))
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
	links := pickerLinks(t, f.get(pathVerify).Body)
	r := f.get(links["authenticator_app"])
	wantStatus(t, r, 200)
	if !strings.Contains(string(r.Body), "Verify with an authenticator app") || strings.Contains(string(r.Body), "Resend code") {
		t.Errorf("page:\n%s", r.Body)
	}
	if len(f.s.MFADeliveries()) != 0 {
		t.Error("nothing should be sent")
	}
	// the authenticator still works, with no code ever sent
	wantSuccess(t, f.verify("authenticator_app", f.s.CurrentTOTP(), csrfToken(t, r.Body)))
}

func TestPickerLanding(t *testing.T) {
	f := newMFAFlow(t, WithMFAPickerLanding())
	if loc := f.login(); loc != pathVerify {
		t.Fatalf("login redirects to %q, want the picker", loc)
	}
	r := f.get(pathVerify)
	wantStatus(t, r, 200)
	if len(f.s.MFADeliveries()) != 0 {
		t.Fatal("nothing is sent before a method is chosen")
	}
	r = f.get(pickerLinks(t, r.Body)["sms"])
	wantStatus(t, r, 200)
	wantSuccess(t, f.verify("sms", f.s.LastMFACode("sms"), csrfToken(t, r.Body)))
}

func TestUnknownMethod(t *testing.T) {
	f := newMFAFlow(t)
	f.login()
	r := f.get("/login/two_factor_authentication/new?type=carrier_pigeon")
	if r.StatusCode != http.StatusNotFound || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") {
		t.Errorf("status = %d, content type %q", r.StatusCode, r.Header.Get("Content-Type"))
	}
	r = f.postForm("/login/two_factor_authentication/new?type=carrier_pigeon", "x")
	wantStatus(t, r, 404)
}

func TestLastUsedMethodIsRemembered(t *testing.T) {
	s := newTestServer(t)

	// Initially the authenticator app.
	f := &mfaFlow{t: t, s: s, c: newClient()}
	if m := redirectMethod(t, f.login()); m != "authenticator_app" {
		t.Fatalf("first login redirects to %q", m)
	}

	// Log in via SMS (picker), verify.
	r := f.get(pickerLinks(t, f.get(pathVerify).Body)["sms"])
	wantSuccess(t, f.verify("sms", s.LastMFACode("sms"), csrfToken(t, r.Body)))

	// The next login, in a new session, goes straight to sms.
	f2 := &mfaFlow{t: t, s: s, c: newClient()}
	if m := redirectMethod(t, f2.login()); m != "sms" {
		t.Fatalf("second login redirects to %q, want sms", m)
	}
	// An abandoned challenge does not change the memory, a TOTP login does.
	f3 := &mfaFlow{t: t, s: s, c: newClient()}
	if m := redirectMethod(t, f3.login()); m != "sms" {
		t.Fatalf("redirect = %q", m)
	}
	r = f3.get(pickerLinks(t, f3.get(pathVerify).Body)["authenticator_app"])
	wantSuccess(t, f3.verify("authenticator_app", s.CurrentTOTP(), csrfToken(t, r.Body)))
	if m := redirectMethod(t, (&mfaFlow{t: t, s: s, c: newClient()}).login()); m != "authenticator_app" {
		t.Fatalf("redirect after TOTP login = %q", m)
	}
}

func TestWithLastMFAMethod(t *testing.T) {
	f := newMFAFlow(t, WithLastMFAMethod("email"))
	if m := redirectMethod(t, f.login()); m != "email" {
		t.Fatalf("redirect = %q", m)
	}
	defer func() {
		if recover() == nil {
			t.Error("an unknown method must panic")
		}
	}()
	WithLastMFAMethod("fax")
}

func TestWrongTokensAreRejected(t *testing.T) {
	f := newMFAFlow(t, WithLastMFAMethod("sms"))
	r := f.get(f.login())
	tok := csrfToken(t, r.Body)
	code := f.s.LastMFACode("sms")

	for name, bad := range map[string]string{"junk": "nope", "empty": "", "stale": strings.Repeat("0", 64)} {
		if r := f.verify("sms", code, bad); r.StatusCode != http.StatusForbidden {
			t.Errorf("verify with %s token: status = %d, want 403", name, r.StatusCode)
		}
		if r := f.postForm(pathSMS, bad, "context", "resend"); r.StatusCode != http.StatusForbidden {
			t.Errorf("resend with %s token: status = %d, want 403", name, r.StatusCode)
		}
	}
	if got := len(f.s.MFADeliveries()); got != 1 {
		t.Errorf("deliveries = %d, want 1: rejected posts must not send codes", got)
	}
	// The token alone is not enough: the _csrf_token cookie must match too.
	cookies := map[string]string{}
	for _, ck := range f.c.Jar.Cookies(mustURL(t, f.s.URL())) {
		cookies[ck.Name] = ck.Value
	}
	h := formHdr()
	h["Cookie"] = sessionCookie + "=" + cookies[sessionCookie]
	r = do(t, &http.Client{CheckRedirect: f.c.CheckRedirect}, "POST", f.s.URL()+pathVerify,
		formBody("_csrf_token", tok, "type", "sms", "code", code), h)
	wantStatus(t, r, 403)
	// The right token verifies, and no X-CSRF-Token header is involved.
	wantSuccess(t, f.verify("sms", code, tok))

	// The failure page.
	if r := f.postForm(pathEmail, "junk"); !strings.Contains(string(r.Body), "Invalid CSRF token") {
		t.Errorf("CSRF failure body: %s", r.Body)
	}
}

func TestPostsWithoutLoginAreRejected(t *testing.T) {
	s := newTestServer(t)
	f := &mfaFlow{t: t, s: s, c: newClient()}
	r := f.postForm(pathSMS, "x", "context", "resend")
	wantStatus(t, r, 403)
	if len(s.MFADeliveries()) != 0 {
		t.Error("nothing should be sent")
	}
	r = f.get(pathVerify)
	wantStatus(t, r, 302)
	r = f.get(pathSMS)
	wantStatus(t, r, 302)
}

func TestMFACodeExpiry(t *testing.T) {
	now := fixedNow
	f := newMFAFlow(t, WithLastMFAMethod("sms"), WithClock(func() time.Time { return now }))
	r := f.get(f.login())
	tok := csrfToken(t, r.Body)
	old := f.s.LastMFACode("sms")

	now = now.Add(10*time.Minute - time.Second)
	wantSuccess(t, f.verify("sms", old, tok)) // still valid at 9:59

	// Expired after 10 minutes; a code sent later is valid.
	f2 := newMFAFlow(t, WithLastMFAMethod("sms"), WithClock(func() time.Time { return now }))
	r = f2.get(f2.login())
	tok = csrfToken(t, r.Body)
	first := f2.s.LastMFACode("sms")
	now = now.Add(10 * time.Minute)
	wantWrongCode(t, f2.verify("sms", first, tok), "sms")
	r = f2.get(pickerLinks(t, f2.get(pathVerify).Body)["sms"])
	second := f2.s.LastMFACode("sms")
	if second == first {
		t.Fatal("codes must differ")
	}
	dl := f2.s.MFADeliveries()
	if !dl[1].At.Equal(now.Truncate(time.Second)) {
		t.Errorf("delivery time = %v, want %v", dl[1].At, now)
	}
	wantWrongCode(t, f2.verify("sms", first, csrfToken(t, r.Body)), "sms")
	wantSuccess(t, f2.verify("sms", second, csrfToken(t, r.Body)))
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
	tok := csrfToken(t, r.Body)
	// No code was ever sent, so no code verifies.
	wantWrongCode(t, g.verify("sms", "000000", tok), "sms")
	g.get(loc)
	g.resend(pathSMS, tok)
	if dl := g.s.MFADeliveries(); len(dl) != 1 || dl[0].Trigger != "resend" {
		t.Fatalf("deliveries = %+v", dl)
	}
	wantSuccess(t, g.verify("sms", g.s.LastMFACode("sms"), tok))
}

func TestMFACodesAreSixDigits(t *testing.T) {
	f := newMFAFlow(t, WithLastMFAMethod("sms"))
	r := f.get(f.login())
	tok := csrfToken(t, r.Body)
	seen := map[string]bool{}
	re := regexp.MustCompile(`^\d{6}$`)
	for range 40 {
		f.resend(pathSMS, tok)
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
	tok := csrfToken(t, r.Body)
	code := f.s.LastMFACode("sms")
	wantSuccess(t, f.verify("sms", code, tok))
	for _, rq := range f.s.Requests() {
		if strings.Contains(rq.Body, code) || strings.Contains(rq.Body, tok) {
			t.Fatalf("request log leaks a secret: %+v", rq)
		}
	}
}
