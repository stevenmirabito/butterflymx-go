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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	fixtureHost = "https://accounts.butterflymx.com"

	// CSRF values from testdata/accounts.
	loginMeta, loginForm = "fkv2I8_q5mcTMT77_Cv1ha7hbRctd5iPsnEDHu8A25EXSFbJUN1W38QNctRLtdO9omTWXh6R6wIU0EgBS-YpZH", "zICjYksQtNyHKEdDtEWa-W0aFOvuoRxouW8ZBU2QbdzHHZiW-Wa5q-H8Kd_WsOE8A_SJKP5SrNe62Q09WoxbP1"
	mfaMeta, mfaForm     = "QPQh--sb2ZDTEkZ_yxsKknONGWDi6DcFMA-xjoL2_poSTmjDVg88ihGWBrlTbf7zDK4rThFBw1vjaPOIbGjPX2", "S0XbjOaW8cOL_bu45DcEKmGPJr8tAIJmOAVUM-pnBiFF5t4PH4JyEpxSV_LClD9NUfhmANRAi_T9vhrIdoQBfE"
	retryMeta, retryForm = "kQuvTIs0DNgoS1im8j7FLUwazrSAGDvLGDidSo6NSydaGkWlJ4l6M0K3hldYMIOc20zSOrECPyjDGnkUc2z1qS", "54po-KqxG0ODeXMeh9EcW2A7uaZnU5ZsqcE2B1UsKgPv049eOGUGnvrJ5f3XCIDo5ytXlNT3AH6jYOFg75_EWQ"

	testEmail, testPassword, testCode = "resident@example.com", "hunter2-secret", "123456"
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
	f.writeBody(w, srvURL, nil)
}

func (f *fixture) writeBody(w http.ResponseWriter, srvURL string, edit func(string) string) {
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
	if edit != nil {
		body = edit(body)
	}
	w.WriteHeader(f.Response.Status)
	_, _ = w.Write([]byte(body))
}

// fake emulates accounts + API on one server.
type fake struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	challenge string // code_challenge from the authorize request
	query     string // raw authorize query
	state     string
	session   int

	// behaviour switches
	loginMode     string // "2fa" (default), "turbo", "turbo-redirect", "badcreds", "weird", "redirect"
	stateOverride string
	refreshMode   string // "rotate", "norotate", "invalid_grant"
	denizenStatus []int  // statuses to return before succeeding
	denizenDelay  time.Duration
	apiTokens     bool // issue distinct api tokens

	// counters
	requests, exchanges, denizens, refreshes, regions, logouts atomic.Int32
	lastDenizenAccess                                          atomic.Value
	lastRefreshToken                                           atomic.Value

	// Two-factor emulation.
	defaultMFA    string // method of the login redirect: "authenticator_app" (default), "sms", "email" or an unknown one
	pickerMode    string // "" (picker page), "redirect-once", "redirect", "garbage", "no-sms"
	pickerRedirs  int
	mfaLog        []string // "GET new type=sms", "GET picker", "POST choose type=email", "POST resend type=sms", "POST verify type=sms"
	cur           servedPage
	pickerTokens  map[string]string // method -> token of the picker form served last
	lastResendRaw string            // raw body of the last resend POST
	lastChooseRaw string            // raw body of the last picker POST

	fxLogin, fxLoginSMS, fxLoginNew, fxToken, fxRegions, fxDenizen *fixture
	fxMFAPage, fxChoose, fxMFA422s, fxMFAOKs                       map[string]*fixture
	fxPicker, fxResendSMS                                          *fixture
}

// servedPage is what the server last rendered for the session: the tokens a
// following POST must use (CSRF tokens are per form).
type servedPage struct {
	mfaType, meta, verify, resend string
}

var (
	metaRe  = regexp.MustCompile(`content="([^"]+)" name="csrf-token"`)
	tokenRe = regexp.MustCompile(`name="authenticity_token" type="hidden" value="([^"]+)"`)
	pickRe  = regexp.MustCompile(`(?s)<form action="[^"]*\?type=(\w+)" method="post">.*?name="authenticity_token" type="hidden" value="([^"]+)"`)
	typeRe  = regexp.MustCompile(`id="type" name="type" type="hidden" value="([^"]+)"`)
)

func newFake(t *testing.T) *fake {
	f := &fake{t: t, loginMode: "2fa", refreshMode: "rotate", defaultMFA: "authenticator_app", pickerTokens: map[string]string{}}
	f.fxLogin = loadFixture(t, "accounts/post-login-303.json")
	f.fxLoginSMS = loadFixture(t, "accounts/post-login-303-to-sms.json")
	// Challenge pages, wrong-code pages and successes, by method.
	f.fxMFAPage = map[string]*fixture{
		"authenticator_app": loadFixture(t, "accounts/get-two-factor-new-200.json"),
		"sms":               loadFixture(t, "accounts/get-two-factor-new-200-sms.json"),
		"email":             loadFixture(t, "accounts/post-two-factor-new-200-email.json"),
	}
	f.fxMFA422s = map[string]*fixture{
		"authenticator_app": loadFixture(t, "accounts/post-two-factor-422-wrong-code.json"),
		"sms":               loadFixture(t, "accounts/post-two-factor-422-wrong-code-sms.json"),
		"email":             loadFixture(t, "accounts/post-two-factor-422-wrong-code-email.json"),
	}
	f.fxMFAOKs = map[string]*fixture{
		"authenticator_app": loadFixture(t, "accounts/post-two-factor-200-turbo-stream.json"),
		"sms":               loadFixture(t, "accounts/post-two-factor-200-turbo-stream-sms.json"),
		"email":             loadFixture(t, "accounts/post-two-factor-200-turbo-stream-email.json"),
	}
	f.fxChoose = map[string]*fixture{
		"authenticator_app": f.fxMFAPage["authenticator_app"],
		"sms":               loadFixture(t, "accounts/post-two-factor-new-200-sms.json"),
		"email":             f.fxMFAPage["email"],
	}
	f.fxPicker = loadFixture(t, "accounts/get-two-factor-methods-200.json")
	f.fxResendSMS = loadFixture(t, "accounts/post-two-factor-resend-sms-200.json")
	f.fxLoginNew = loadFixture(t, "accounts/get-login-new-200.json")
	f.fxToken = loadFixture(t, "accounts/post-oauth-token-200.json")
	f.fxRegions = loadFixture(t, "accounts/get-api-mobile-regions-200.json")
	f.fxDenizen = loadFixture(t, "denizen/post-login-200.json")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth/authorize", f.authorize)
	mux.HandleFunc("GET /login/new", f.loginNew)
	mux.HandleFunc("POST /login", f.postLogin)
	mux.HandleFunc("GET /sessions/two_factor_authentication/new", f.mfaNew)
	mux.HandleFunc("GET /sessions/two_factor_authentication", f.mfaPicker)
	mux.HandleFunc("POST /sessions/two_factor_authentication/new", f.postMFAChoose)
	mux.HandleFunc("POST /sessions/two_factor_authentication", f.postMFA)
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

// rotate issues a fresh session cookie (the real server re-issues it on every response).
func (f *fake) rotate(w http.ResponseWriter) {
	f.mu.Lock()
	f.session++
	v := "sess" + strconv.Itoa(f.session)
	f.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "_accounts_session", Value: v, Path: "/", HttpOnly: true})
}

func (f *fake) checkSession(w http.ResponseWriter, r *http.Request) bool {
	c, err := r.Cookie("_accounts_session")
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
		// Final step: bounce to the app with code and state.
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
		w.Header().Set("Location", publicRedirectURI+"?code=AUTHCODE&state="+url.QueryEscape(st))
		w.WriteHeader(http.StatusFound)
		return
	}
	f.mu.Lock()
	f.challenge, f.query, f.state = q.Get("code_challenge"), r.URL.RawQuery, q.Get("state")
	f.mu.Unlock()
	f.rotate(w)
	w.Header().Set("Location", "/login/new")
	w.WriteHeader(http.StatusFound)
}

func (f *fake) loginNew(w http.ResponseWriter, r *http.Request) {
	if !f.checkSession(w, r) || !f.checkUA(w, r) {
		return
	}
	f.rotate(w)
	f.fxLoginNew.write(w, f.srv.URL)
}

func (f *fake) markAuthed(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "authed", Value: "1", Path: "/"})
}

// checkForm validates the CSRF placement and returns the parsed form.
func (f *fake) checkForm(w http.ResponseWriter, r *http.Request, meta, form string) bool {
	if !f.checkSession(w, r) || !f.checkUA(w, r) {
		return false
	}
	if err := r.ParseForm(); err != nil {
		f.fail(w, "parse form: %v", err)
		return false
	}
	if r.Header.Get("X-CSRF-Token") != meta {
		f.fail(w, "X-CSRF-Token = %q, want meta token", r.Header.Get("X-CSRF-Token"))
		return false
	}
	if r.PostForm.Get("authenticity_token") != form {
		f.fail(w, "authenticity_token = %q, want form token", r.PostForm.Get("authenticity_token"))
		return false
	}
	if got := r.Header.Get("Accept"); got != "text/vnd.turbo-stream.html, text/html, application/xhtml+xml" {
		f.fail(w, "Accept = %q", got)
		return false
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded;charset=UTF-8" {
		f.fail(w, "Content-Type = %q", ct)
		return false
	}
	return true
}

func (f *fake) turbo(r *http.Request, action string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fmt.Sprintf(`<turbo-stream location="%s" action="%s"><template></template></turbo-stream>`,
		html.EscapeString("/oauth/authorize?"+f.query), action)
}

func (f *fake) postLogin(w http.ResponseWriter, r *http.Request) {
	if !f.checkForm(w, r, loginMeta, loginForm) {
		return
	}
	for k, v := range map[string]string{"login[email]": testEmail, "login[password]": testPassword, "commit": "Sign in with email"} {
		if r.PostForm.Get(k) != v {
			f.fail(w, "login field %s = %q", k, r.PostForm.Get(k))
			return
		}
	}
	f.rotate(w)
	switch f.loginMode {
	case "2fa":
		switch f.defaultMFA {
		case "authenticator_app":
			f.fxLogin.write(w, f.srv.URL)
		case "sms":
			f.fxLoginSMS.write(w, f.srv.URL)
		default:
			w.Header().Set("Location", "/sessions/two_factor_authentication/new?type="+f.defaultMFA)
			w.WriteHeader(http.StatusSeeOther)
		}
	case "turbo", "turbo-redirect":
		f.markAuthed(w)
		action := "redirect_to"
		if f.loginMode == "turbo-redirect" {
			action = "redirect"
		}
		w.Header().Set("Content-Type", "text/vnd.turbo-stream.html; charset=utf-8")
		_, _ = fmt.Fprint(w, f.turbo(r, action))
	case "redirect":
		f.markAuthed(w)
		w.Header().Set("Location", "/oauth/authorize?"+f.query)
		w.WriteHeader(http.StatusSeeOther)
	case "badcreds":
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = fmt.Fprint(w, f.fxLoginNew.Response.Body.(string))
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

// serveChallenge renders a challenge page and remembers its per-form tokens.
func (f *fake) serveChallenge(w http.ResponseWriter, fx *fixture, status int) {
	body, _ := fx.Response.Body.(string)
	body = strings.ReplaceAll(body, fixtureHost, f.srv.URL)
	cur := servedPage{}
	if m := metaRe.FindStringSubmatch(body); m != nil {
		cur.meta = m[1]
	}
	if m := typeRe.FindStringSubmatch(body); m != nil {
		cur.mfaType = m[1]
	}
	tokens := tokenRe.FindAllStringSubmatch(body, -1)
	if len(tokens) > 0 {
		cur.verify = tokens[0][1]
	}
	if len(tokens) > 1 {
		cur.resend = tokens[1][1]
	}
	f.mu.Lock()
	f.cur = cur
	f.mu.Unlock()
	f.rotate(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (f *fake) mfaNew(w http.ResponseWriter, r *http.Request) {
	if !f.checkSession(w, r) || !f.checkUA(w, r) {
		return
	}
	typ := r.URL.Query().Get("type")
	f.logf("GET new type=%s", typ)
	fx := f.fxMFAPage[typ]
	if fx == nil {
		f.fail(w, "type = %q", typ)
		return
	}
	f.serveChallenge(w, fx, http.StatusOK)
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
		f.rotate(w)
		w.Header().Set("Location", "/login/new")
		w.WriteHeader(http.StatusFound)
		return
	case "garbage":
		f.rotate(w)
		_, _ = fmt.Fprint(w, "<html><body><h1>Maintenance</h1></body></html>")
		return
	}
	body := f.fxPicker.Response.Body.(string)
	if mode == "no-sms" {
		a := strings.Index(body, `<form action="/sessions/two_factor_authentication/new?type=sms"`)
		b := a + strings.Index(body[a:], "</form>") + len("</form>")
		body = body[:a] + body[b:]
	}
	f.mu.Lock()
	f.pickerTokens = map[string]string{}
	for _, m := range pickRe.FindAllStringSubmatch(body, -1) {
		f.pickerTokens[m[1]] = m[2]
	}
	f.mu.Unlock()
	f.rotate(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, body)
}

// checkPlainPost validates a plain form post: no X-CSRF-Token, browser Accept.
func (f *fake) checkPlainPost(w http.ResponseWriter, r *http.Request) bool {
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
	return true
}

// postMFAChoose handles both the picker choice and "Resend code".
func (f *fake) postMFAChoose(w http.ResponseWriter, r *http.Request) {
	if !f.checkPlainPost(w, r) {
		return
	}
	typ := r.URL.Query().Get("type")
	token := r.PostForm.Get("authenticity_token")
	f.mu.Lock()
	cur, want := f.cur, f.pickerTokens[typ]
	f.mu.Unlock()
	if r.PostForm.Get("context") == "resend" {
		f.logf("POST resend type=%s", typ)
		f.mu.Lock()
		f.lastResendRaw = r.PostForm.Encode()
		f.mu.Unlock()
		if token != cur.resend || cur.resend == "" {
			f.fail(w, "resend token = %q, want the resend form's %q", token, cur.resend)
			return
		}
		if cur.mfaType != typ {
			f.fail(w, "resend for %q while the page is for %q", typ, cur.mfaType)
			return
		}
		if typ == "sms" {
			f.serveChallenge(w, f.fxResendSMS, http.StatusOK)
			return
		}
		f.serveChallenge(w, f.fxMFAPage[typ], http.StatusOK)
		return
	}
	f.logf("POST choose type=%s", typ)
	f.mu.Lock()
	f.lastChooseRaw = r.PostForm.Encode()
	f.mu.Unlock()
	if token != want || want == "" {
		f.fail(w, "picker token for %s = %q, want that form's own %q", typ, token, want)
		return
	}
	if len(r.PostForm) != 1 {
		f.fail(w, "picker form has extra fields: %v", r.PostForm)
		return
	}
	fx := f.fxChoose[typ]
	if fx == nil {
		f.fail(w, "type = %q", typ)
		return
	}
	f.serveChallenge(w, fx, http.StatusOK)
}

func (f *fake) postMFA(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	cur := f.cur
	f.mu.Unlock()
	f.logf("POST verify type=%s", r.PostForm.Get("type"))
	if !f.checkForm(w, r, cur.meta, cur.verify) {
		return
	}
	typ := r.PostForm.Get("type")
	if typ != cur.mfaType || r.PostForm.Get("commit") != "Use code" {
		f.fail(w, "mfa fields: %v (page is for %q)", r.PostForm, cur.mfaType)
		return
	}
	if r.PostForm.Get("code") != testCode {
		f.serveChallenge(w, f.fxMFA422s[typ], http.StatusUnprocessableEntity)
		return
	}
	f.rotate(w)
	f.markAuthed(w)
	f.fxMFAOKs[typ].writeBody(w, f.srv.URL, func(string) string { return f.turbo(r, "redirect_to") })
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
