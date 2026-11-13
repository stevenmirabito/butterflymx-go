package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	fixtureHost = "https://accounts.butterflymx.com"

	testEmail, testPassword, testCode = "resident@example.com", "hunter2-secret", "123456"

	// acctID is the opaque account_id of the picker's links.
	acctID = "acct-0123456789"
)

type fixture struct {
	Request struct {
		Method string `json:"method"`
		Path   string `json:"path"`
		Body   any    `json:"body"`
	} `json:"request"`
	Response struct {
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    any               `json:"body"`
	} `json:"response"`
}

func loadFixture(t testing.TB, name string) *fixture {
	t.Helper()
	data, err := os.ReadFile("../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return &f
}

// write replays the fixture response, pointing fixture URLs at srvURL.
func (f *fixture) write(w http.ResponseWriter, srvURL string) {
	for k, v := range f.Response.Headers {
		if k == "etag" {
			continue
		}
		w.Header().Set(k, strings.ReplaceAll(v, fixtureHost, srvURL))
	}
	var body string
	switch b := f.Response.Body.(type) {
	case nil:
	case string:
		body = strings.ReplaceAll(b, fixtureHost, srvURL)
	default:
		raw, _ := json.Marshal(b)
		body = string(raw)
	}
	w.WriteHeader(f.Response.Status)
	_, _ = w.Write([]byte(body))
}

// fake emulates accounts + API on one server. The accounts pages follow the
// structure of the login and two-factor pages captured from production on
// 2026-11-12 (the Node app that replaced the Rails one).
type fake struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	challenge string // code_challenge from the authorize request
	query     string // raw authorize query
	state     string
	session   int
	csrf      string // the token of the page served last (form fields and cookie)
	loginErr  string // one-shot error for the next login page
	seq       int

	// behaviour switches
	loginMode     string // "2fa" (default), "redirect", "badcreds", "badcreds-200", "bounce", "weird"
	stateOverride string
	tokenEcho     string // when set, the code exchange fails with "bad <tokenEcho>" in the description
	tokenRedirect string // when set, the code exchange answers 307 to this URL
	regionsEcho   string // when set, region discovery fails with HTTP 500 and this body
	refreshMode   string // "rotate", "norotate", "invalid_grant"
	denizenStatus []int  // statuses to return before succeeding
	denizenDelay  time.Duration
	apiTokens     bool // issue distinct api tokens

	// counters
	requests, exchanges, denizens, refreshes, regions, logouts atomic.Int32
	lastDenizenAccess                                          atomic.Value
	lastRefreshToken                                           atomic.Value

	// Two-factor emulation.
	defaultMFA   string // method of the login redirect: "authenticator_app" (default), "sms", "email", "picker" (no default) or an unknown one
	pickerMode   string // "" (picker page), "redirect-once", "redirect", "garbage", "no-sms", "app-only"
	wrongMode    string // how a wrong code is answered: "" (200 re-render), "redirect", "422", "login" (session lost)
	resendMode   string // how the resend form is answered: "" (200 challenge page), "redirect"
	pickerRedirs int
	mfaLog       []string // "GET new type=sms", "GET picker", "GET choose type=email", "POST resend type=sms", "POST verify type=sms"
	cur          servedPage
	lastResend   string // raw body of the last resend POST
	lastVerify   string // raw body of the last verify POST

	fxToken, fxRegions, fxDenizen *fixture
}

// servedPage is what the server last rendered for the session.
type servedPage struct {
	mfaType string
}

func newFake(t *testing.T) *fake {
	f := &fake{t: t, loginMode: "2fa", refreshMode: "rotate", defaultMFA: "authenticator_app"}
	f.fxToken = loadFixture(t, "accounts/post-oauth-token-200.json")
	f.fxRegions = loadFixture(t, "accounts/get-api-mobile-regions-200.json")
	f.fxDenizen = loadFixture(t, "denizen/post-login-200.json")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth/authorize", f.authorize)
	mux.HandleFunc("GET /login/new", f.loginNew)
	mux.HandleFunc("POST /login", f.postLogin)
	mux.HandleFunc("GET /login/two_factor_authentication/new", f.mfaNew)
	mux.HandleFunc("GET /login/two_factor_authentication", f.mfaPicker)
	mux.HandleFunc("POST /login/two_factor_authentication/new", f.postMFAResend)
	mux.HandleFunc("POST /login/two_factor_authentication", f.postMFA)
	mux.HandleFunc("POST /oauth/token", f.token)
	mux.HandleFunc("GET /api/mobile/regions", f.regionsH)
	mux.HandleFunc("POST /denizen/v1/login", f.denizen)
	mux.HandleFunc("DELETE /denizen/v1/logout", func(w http.ResponseWriter, r *http.Request) {
		f.logouts.Add(1)
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		loadFixture(t, "denizen/delete-logout-200.json").write(w, f.srv.URL)
	})
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) cfg() Config {
	c := Production
	c.AccountsURL, c.APIURL = f.srv.URL, f.srv.URL
	return c
}

func (f *fake) fail(w http.ResponseWriter, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	f.t.Errorf("fake server: %s", msg)
	http.Error(w, msg, http.StatusTeapot)
}

// rotate issues a fresh session cookie (the real server re-issues it on every
// response) and, for a rendered page, a fresh CSRF token whose value is also
// the _csrf_token cookie (double submit). It returns the page's token.
func (f *fake) rotate(w http.ResponseWriter, page bool) string {
	f.mu.Lock()
	f.session++
	v := "sess" + strconv.Itoa(f.session)
	if page {
		f.seq++
		f.csrf = fmt.Sprintf("%064x", f.seq*7919)
	}
	tok := f.csrf
	f.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "identity_session", Value: v, Path: "/", HttpOnly: true})
	if tok != "" {
		http.SetCookie(w, &http.Cookie{Name: "_csrf_token", Value: tok, Path: "/"})
	}
	return tok
}

func (f *fake) checkSession(w http.ResponseWriter, r *http.Request) bool {
	c, err := r.Cookie("identity_session")
	f.mu.Lock()
	want := "sess" + strconv.Itoa(f.session)
	f.mu.Unlock()
	if err != nil || c.Value != want {
		f.fail(w, "%s %s: stale or missing session cookie (%v)", r.Method, r.URL.Path, err)
		return false
	}
	return true
}

func (f *fake) checkUA(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("User-Agent") != DefaultWebUserAgent {
		f.fail(w, "web user agent not used: %q", r.Header.Get("User-Agent"))
		return false
	}
	return true
}

func (f *fake) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	want := map[string]string{
		"client_id": publicClientID, "redirect_uri": publicRedirectURI, "response_type": "code",
		"scope": "openid profile", "code_challenge_method": "S256", "prompt": "login",
	}
	for k, v := range want {
		if q.Get(k) != v {
			if k == "prompt" && q.Get(k) == "" {
				continue // the post-login hop drops prompt=login
			}
			f.fail(w, "authorize %s=%q, want %q", k, q.Get(k), v)
			return
		}
	}
	for _, k := range []string{"code_challenge", "state", "nonce"} {
		if len(q.Get(k)) != 43 {
			f.fail(w, "authorize %s has length %d, want 43", k, len(q.Get(k)))
			return
		}
	}
	if !f.checkUA(w, r) {
		return
	}
	if _, err := r.Cookie("authed"); err == nil {
		// Final step: the "Returning to app" page, which links to the app.
		if !f.checkSession(w, r) {
			return
		}
		f.mu.Lock()
		f.challenge, f.state = q.Get("code_challenge"), q.Get("state")
		st := f.state
		if f.stateOverride != "" {
			st = f.stateOverride
		}
		f.mu.Unlock()
		f.rotate(w, false)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		link := publicRedirectURI + "?code=AUTHCODE&state=" + url.QueryEscape(st)
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Returning to app…</title></head><body><h1>Returning to app…</h1><p>Returning to the app… <a href="%s">Tap here if nothing happens</a></p></body></html>`, html.EscapeString(link))
		return
	}
	f.mu.Lock()
	f.challenge, f.query, f.state = q.Get("code_challenge"), r.URL.RawQuery, q.Get("state")
	f.mu.Unlock()
	f.rotate(w, true)
	w.Header().Set("Location", "/login/new")
	w.WriteHeader(http.StatusFound)
}

// authorizeBack is the Location after a successful sign-in: the authorize
// query without prompt=login.
func (f *fake) authorizeBack() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	q, _ := url.ParseQuery(f.query)
	q.Del("prompt")
	return "/oauth/authorize?" + q.Encode()
}

func hiddenIn(name, value string) string {
	return `<input type="hidden" name="` + name + `" value="` + html.EscapeString(value) + `" />`
}

func (f *fake) loginHTML(tok, errMsg string) string {
	pwErr := ""
	if errMsg != "" {
		pwErr = `<ul class="select-none text-sm text-red-1">` + html.EscapeString(errMsg) + `</ul>`
	}
	return `<!DOCTYPE html><html class="h-full" lang="en"><head><meta charset="utf-8"><title>ButterflyMX - Sign in</title>
<script nonce="abc">window.dataLayer = window.dataLayer || [];</script></head><body><main><h1>Sign in</h1>
<form autocomplete="off" novalidate action="/login" method="post">` + hiddenIn("_csrf_token", tok) + hiddenIn("return_to", f.authorizeBack()) + `
<input type="email" name="email" id="login_email" value="" />
<input type="password" name="password" id="login_password" /><button type="button" class="toggle-pw"></button>` + pwErr + `
<a href="/password/new">Forgot password?</a><input type="submit" name="commit" value="Sign in with email" /></form>
<form method="post" action="/sso/google">` + hiddenIn("_csrf_token", tok) + `<button type="submit">Google</button></form>
</main></body></html>`
}

func (f *fake) loginNew(w http.ResponseWriter, r *http.Request) {
	if !f.checkSession(w, r) || !f.checkUA(w, r) {
		return
	}
	tok := f.rotate(w, true)
	f.mu.Lock()
	msg := f.loginErr
	f.loginErr = ""
	f.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, f.loginHTML(tok, msg))
}

func (f *fake) markAuthed(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "authed", Value: "1", Path: "/"})
}

// checkPost validates a plain form post as the browser makes it: session
// cookie, web user agent, browser Accept, urlencoded body, no X-CSRF-Token
// header, and the form's _csrf_token equal to the page token and the cookie.
func (f *fake) checkPost(w http.ResponseWriter, r *http.Request) bool {
	if !f.checkSession(w, r) || !f.checkUA(w, r) {
		return false
	}
	if err := r.ParseForm(); err != nil {
		f.fail(w, "parse form: %v", err)
		return false
	}
	if v, ok := r.Header["X-Csrf-Token"]; ok {
		f.fail(w, "plain form post must not send X-CSRF-Token (got %q)", v)
		return false
	}
	if got := r.Header.Get("Accept"); got != "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" {
		f.fail(w, "Accept = %q", got)
		return false
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		f.fail(w, "Content-Type = %q", ct)
		return false
	}
	f.mu.Lock()
	want := f.csrf
	f.mu.Unlock()
	c, err := r.Cookie("_csrf_token")
	if want == "" || r.PostForm.Get("_csrf_token") != want || err != nil || c.Value != want {
		f.fail(w, "csrf: form %q cookie %v, want the page token %q", r.PostForm.Get("_csrf_token"), c, want)
		return false
	}
	return true
}

func (f *fake) postLogin(w http.ResponseWriter, r *http.Request) {
	if !f.checkPost(w, r) {
		return
	}
	for k, v := range map[string]string{"email": testEmail, "password": testPassword, "commit": "Sign in with email"} {
		if r.PostForm.Get(k) != v {
			f.fail(w, "login field %s = %q", k, r.PostForm.Get(k))
			return
		}
	}
	if !strings.HasPrefix(r.PostForm.Get("return_to"), "/oauth/authorize?") {
		f.fail(w, "return_to = %q", r.PostForm.Get("return_to"))
		return
	}
	if _, ok := r.PostForm["login[email]"]; ok {
		f.fail(w, "old login[email] field sent")
		return
	}
	f.rotate(w, false)
	switch f.loginMode {
	case "2fa":
		switch f.defaultMFA {
		case "picker":
			w.Header().Set("Location", "/login/two_factor_authentication")
		default:
			w.Header().Set("Location", "/login/two_factor_authentication/new?type="+f.defaultMFA)
		}
		w.WriteHeader(http.StatusFound)
	case "redirect":
		f.markAuthed(w)
		w.Header().Set("Location", f.authorizeBack())
		w.WriteHeader(http.StatusFound)
	case "badcreds":
		f.mu.Lock()
		f.loginErr = "Invalid email or password"
		f.mu.Unlock()
		w.Header().Set("Location", "/login/new")
		w.WriteHeader(http.StatusSeeOther)
	case "bounce":
		w.Header().Set("Location", "/login/new")
		w.WriteHeader(http.StatusSeeOther)
	case "badcreds-200":
		tok := f.rotate(w, true)
		_, _ = fmt.Fprint(w, f.loginHTML(tok, "Invalid email or password"))
	case "weird":
		_, _ = fmt.Fprintf(w, "<html><body><h1>Please solve this CAPTCHA %s %s</h1></body></html>", testEmail, testPassword)
	}
}

func (f *fake) logf(format string, args ...any) {
	f.mu.Lock()
	f.mfaLog = append(f.mfaLog, fmt.Sprintf(format, args...))
	f.mu.Unlock()
}

// log returns a copy of the recorded two-factor requests.
func (f *fake) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.mfaLog...)
}

// challengeHTML renders the challenge page of typ with a fresh CSRF token.
func (f *fake) challengeHTML(w http.ResponseWriter, typ, errMsg string) string {
	tok := f.rotate(w, true)
	f.mu.Lock()
	f.cur = servedPage{mfaType: typ}
	f.mu.Unlock()
	hint := "Enter the verification code the authenticator app provides"
	switch typ {
	case "sms":
		hint = "A 6-digit code has been sent to your phone number ******0100"
	case "email":
		hint = "A 6-digit code has been sent to your email"
	}
	fieldErr := ""
	if errMsg != "" {
		fieldErr = `<ul class="text-red-1">` + html.EscapeString(errMsg) + `</ul>`
	}
	resend := ""
	if typ != "authenticator_app" {
		resend = `<form method="post" action="/login/two_factor_authentication/new?type=` + typ + `">` +
			hiddenIn("_csrf_token", tok) + hiddenIn("context", "resend") + `<button type="submit">Resend code</button></form>`
	}
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>ButterflyMX - Verify with ` + typ + `</title></head><body><main>
<h1>Verify</h1><h2>` + hint + `</h2>
<form action="/login/two_factor_authentication" method="post">` + hiddenIn("_csrf_token", tok) + hiddenIn("type", typ) + `
<input type="text" name="code" id="code" />` + fieldErr + `<input type="submit" value="Use code" /></form>` + resend + `
<a href="/login/two_factor_authentication">Verify another way</a></main></body></html>`
}

func (f *fake) serveChallenge(w http.ResponseWriter, typ, errMsg string, status int) {
	body := f.challengeHTML(w, typ, errMsg)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (f *fake) mfaNew(w http.ResponseWriter, r *http.Request) {
	if !f.checkSession(w, r) || !f.checkUA(w, r) {
		return
	}
	typ := r.URL.Query().Get("type")
	if r.URL.Query().Get("account_id") != "" {
		if r.URL.Query().Get("account_id") != acctID {
			f.fail(w, "account_id = %q", r.URL.Query().Get("account_id"))
			return
		}
		f.logf("GET choose type=%s", typ)
	} else {
		f.logf("GET new type=%s", typ)
	}
	switch typ {
	case "authenticator_app", "sms", "email":
		f.serveChallenge(w, typ, "", http.StatusOK)
	default:
		f.fail(w, "type = %q", typ)
	}
}

func (f *fake) mfaPicker(w http.ResponseWriter, r *http.Request) {
	if !f.checkSession(w, r) || !f.checkUA(w, r) {
		return
	}
	f.logf("GET picker")
	f.mu.Lock()
	mode := f.pickerMode
	if mode == "redirect-once" && f.pickerRedirs == 0 {
		f.pickerRedirs++
		mode = "redirect"
	}
	f.mu.Unlock()
	switch mode {
	case "redirect":
		f.rotate(w, false)
		w.Header().Set("Location", "/login/new")
		w.WriteHeader(http.StatusFound)
		return
	case "garbage":
		f.rotate(w, false)
		_, _ = fmt.Fprint(w, "<html><body><h1>Maintenance</h1></body></html>")
		return
	}
	methods := []string{"email", "sms", "authenticator_app"}
	switch mode {
	case "no-sms":
		methods = []string{"email", "authenticator_app"}
	case "app-only":
		methods = []string{"authenticator_app"}
	case "sms-email":
		methods = []string{"email", "sms"}
	case "unknown-only":
		methods = []string{"webauthn"}
	case "echo":
		f.rotate(w, false)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, "<html><body>Error for %s, ref 12345678, code %s</body></html>", testEmail, testCode)
		return
	}
	var links strings.Builder
	for _, m := range methods {
		fmt.Fprintf(&links, `<a href="/login/two_factor_authentication/new?type=%s&amp;account_id=%s"><h3>%s</h3></a>`, m, acctID, m)
	}
	f.rotate(w, true)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>ButterflyMX - How do you want to verify your account?</title></head><body>
<h1>How do you want to verify your account?</h1>%s<a href="mailto:support@butterflymx.com">support</a></body></html>`, links.String())
}

// postMFAResend handles "Resend code".
func (f *fake) postMFAResend(w http.ResponseWriter, r *http.Request) {
	if !f.checkPost(w, r) {
		return
	}
	typ := r.URL.Query().Get("type")
	f.logf("POST resend type=%s", typ)
	f.mu.Lock()
	f.lastResend = r.PostForm.Encode()
	cur := f.cur
	f.mu.Unlock()
	if r.PostForm.Get("context") != "resend" {
		f.fail(w, "resend context = %q", r.PostForm.Get("context"))
		return
	}
	if cur.mfaType != typ {
		f.fail(w, "resend for %q while the page is for %q", typ, cur.mfaType)
		return
	}
	if f.resendMode == "maintenance" {
		f.rotate(w, false)
		_, _ = fmt.Fprint(w, "<html><body><h1>Maintenance</h1></body></html>")
		return
	}
	if f.resendMode == "redirect" {
		f.rotate(w, false)
		w.Header().Set("Location", "/login/two_factor_authentication/new?type="+typ)
		w.WriteHeader(http.StatusFound)
		return
	}
	f.serveChallenge(w, typ, "", http.StatusOK)
}

func (f *fake) postMFA(w http.ResponseWriter, r *http.Request) {
	if !f.checkPost(w, r) {
		return
	}
	typ := r.PostForm.Get("type")
	f.logf("POST verify type=%s", typ)
	f.mu.Lock()
	cur := f.cur
	f.lastVerify = r.PostForm.Encode()
	f.mu.Unlock()
	if typ != cur.mfaType {
		f.fail(w, "mfa fields: %v (page is for %q)", r.PostForm, cur.mfaType)
		return
	}
	if r.PostForm.Get("code") != testCode {
		switch f.wrongMode {
		case "redirect":
			f.rotate(w, false)
			w.Header().Set("Location", "/login/two_factor_authentication/new?type="+typ)
			w.WriteHeader(http.StatusFound)
		case "maintenance":
			// An unusable page that still replaces the session cookie.
			f.rotate(w, false)
			_, _ = fmt.Fprint(w, "<html><body><h1>Maintenance</h1></body></html>")
		case "login":
			f.rotate(w, false)
			w.Header().Set("Location", "/login/new")
			w.WriteHeader(http.StatusFound)
		case "422":
			f.serveChallenge(w, typ, "Invalid verification code", http.StatusUnprocessableEntity)
		default:
			f.serveChallenge(w, typ, "Invalid verification code", http.StatusOK)
		}
		return
	}
	f.rotate(w, false)
	f.markAuthed(w)
	w.Header().Set("Location", f.authorizeBack())
	w.WriteHeader(http.StatusFound)
}

func (f *fake) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		f.fail(w, "parse: %v", err)
		return
	}
	if r.PostForm.Get("client_id") != publicClientID {
		f.fail(w, "client_id")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		f.exchanges.Add(1)
		if f.tokenRedirect != "" {
			w.Header().Set("Location", f.tokenRedirect)
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		if f.tokenEcho != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, `{"error":"invalid_grant","error_description":"bad %s"}`, f.tokenEcho)
			return
		}
		v := r.PostForm.Get("code_verifier")
		sum := sha256.Sum256([]byte(v))
		f.mu.Lock()
		challenge := f.challenge
		f.mu.Unlock()
		if len(v) != 43 || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			f.fail(w, "PKCE mismatch: S256(%q) != %q", v, challenge)
			return
		}
		if r.PostForm.Get("code") != "AUTHCODE" || r.PostForm.Get("redirect_uri") != publicRedirectURI {
			f.fail(w, "code/redirect_uri: %v", r.PostForm)
			return
		}
		f.fxToken.write(w, f.srv.URL)
	case "refresh_token":
		f.refreshes.Add(1)
		f.lastRefreshToken.Store(r.PostForm.Get("refresh_token"))
		w.Header().Set("Content-Type", "application/json")
		switch f.refreshMode {
		case "invalid_grant":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `{"error":"invalid_grant","error_description":"The provided authorization grant is invalid."}`)
		case "norotate":
			_, _ = fmt.Fprint(w, `{"access_token":"REFRESHED_ACCESS","token_type":"Bearer","expires_in":86400,"created_at":1}`)
		default:
			_, _ = fmt.Fprint(w, `{"access_token":"REFRESHED_ACCESS","token_type":"Bearer","expires_in":86400,"refresh_token":"ROTATED_REFRESH","created_at":1}`)
		}
	default:
		f.fail(w, "grant_type %q", r.PostForm.Get("grant_type"))
	}
}

func (f *fake) regionsH(w http.ResponseWriter, r *http.Request) {
	f.regions.Add(1)
	if f.regionsEcho != "" {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(w, f.regionsEcho)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		f.fail(w, "regions without bearer")
		return
	}
	f.fxRegions.write(w, f.srv.URL)
}

func (f *fake) denizen(w http.ResponseWriter, r *http.Request) {
	n := int(f.denizens.Add(1))
	if f.denizenDelay > 0 {
		time.Sleep(f.denizenDelay)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		Device      struct {
			Platform string   `json:"platform"`
			Version  string   `json:"version"`
			Locales  []string `json:"locales"`
			Token    string   `json:"token"`
		} `json:"device"`
	}
	if err := json.UnmarshalRead(r.Body, &body); err != nil {
		f.fail(w, "denizen body: %v", err)
		return
	}
	if body.Device.Platform != "ios" || body.Device.Version != "1001.125.2" || len(body.Device.Locales) != 1 || body.Device.Token != "" {
		f.fail(w, "device = %+v", body.Device)
		return
	}
	if r.Header.Get("User-Agent") != DefaultUserAgent {
		f.fail(w, "api user agent %q", r.Header.Get("User-Agent"))
		return
	}
	f.lastDenizenAccess.Store(body.AccessToken)
	if n <= len(f.denizenStatus) && f.denizenStatus[n-1] != 200 {
		w.WriteHeader(f.denizenStatus[n-1])
		return
	}
	if f.apiTokens {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"token":"API_TOKEN_%d"}`, n)
		return
	}
	f.fxDenizen.write(w, f.srv.URL)
}
