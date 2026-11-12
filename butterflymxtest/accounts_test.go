package butterflymxtest

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTOTPRFC6238Vector(t *testing.T) {
	// RFC 6238 appendix B, SHA1, T=59s: 94287082 -> last six digits 287082.
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	if got := totpCode(secret, 59/30); got != "287082" {
		t.Fatalf("totp = %s, want 287082", got)
	}
	now := time.Unix(59, 0)
	if !totpValid(secret, "287082", now) || totpValid(secret, "000000", now) {
		t.Fatal("totpValid mismatch")
	}
	// previous and next windows are accepted, two windows away is not.
	if !totpValid(secret, totpCode(secret, 0), now) || !totpValid(secret, totpCode(secret, 2), now) {
		t.Fatal("neighbouring windows must be accepted")
	}
	if totpValid(secret, totpCode(secret, 4), now) {
		t.Fatal("window +3 must be rejected")
	}
}

func TestFullLoginWithTOTP(t *testing.T) {
	s := newTestServer(t)
	tk := login(t, s)

	if n := strings.Count(tk.Access, "."); n != 2 {
		t.Errorf("access token is not JWT shaped: %q", tk.Access)
	}
	if tk.Raw["token_type"] != "Bearer" || tk.Raw["expires_in"] != float64(86400) || tk.Raw["scope"] != "openid profile" {
		t.Errorf("token response = %v", tk.Raw)
	}
	if strings.Contains(tk.API, ".") || len(tk.API) < 300 {
		t.Errorf("API token shape: %d chars %q", len(tk.API), tk.API)
	}

	// Secrets are redacted in the request log.
	for _, rq := range s.Requests() {
		for _, secret := range []string{DefaultPassword, tk.Access, tk.Refresh, tk.API} {
			if strings.Contains(rq.Body, secret) || strings.Contains(rq.Header.Get("Authorization"), secret) {
				t.Fatalf("request %s %s leaks a secret: %+v", rq.Method, rq.Path, rq)
			}
		}
	}
	var sawLogin bool
	for _, rq := range s.Requests() {
		if rq.Path == "/login" {
			sawLogin = true
			if !strings.Contains(rq.Body, "login%5Bemail%5D=resident%40example.com") || !strings.Contains(rq.Body, "REDACTED") || rq.Status != 303 {
				t.Errorf("login record = %+v", rq)
			}
		}
	}
	if !sawLogin {
		t.Error("login request not recorded")
	}
}

func TestLoginWithoutMFA(t *testing.T) {
	s := newTestServer(t, WithoutMFA())
	tk := login(t, s)
	if tk.API == "" {
		t.Fatal("no API token")
	}
}

func TestWrongPassword(t *testing.T) {
	s := newTestServer(t)
	c := newClient()
	do(t, c, "GET", authorizeURL(s.URL(), newPKCE(), "st", true), nil, nil)
	r := do(t, c, "GET", s.URL()+"/login/new", nil, nil)
	meta, form := csrfTokens(t, r.Body)
	r = do(t, c, "POST", s.URL()+"/login", formBody("authenticity_token", form, "login[email]", DefaultEmail, "login[password]", "nope", "commit", "Sign in with email"), formHdr(meta))
	wantStatus(t, r, 422)
	body := string(r.Body)
	if !strings.Contains(body, `action="/login"`) || !strings.Contains(body, "Invalid email or password.") {
		t.Fatalf("expected the login form with an error:\n%s", body)
	}
	if m2, f2 := csrfTokens(t, r.Body); m2 == meta || f2 == form {
		t.Error("expected fresh CSRF tokens")
	}
}

func TestCSRFIsEnforced(t *testing.T) {
	s := newTestServer(t)
	c := newClient()
	r := do(t, c, "GET", s.URL()+"/login/new", nil, nil)
	meta, form := csrfTokens(t, r.Body)
	body := formBody("authenticity_token", form, "login[email]", DefaultEmail, "login[password]", DefaultPassword)

	for name, tc := range map[string]struct {
		c   func() reply
		msg string
	}{
		"no header": {func() reply {
			h := formHdr(meta)
			delete(h, "X-CSRF-Token")
			return do(t, c, "POST", s.URL()+"/login", body, h)
		}, "header missing"},
		"bad header": {func() reply { return do(t, c, "POST", s.URL()+"/login", body, formHdr("bogus")) }, "header wrong"},
		"no session": {func() reply { return do(t, newClient(), "POST", s.URL()+"/login", body, formHdr(meta)) }, "no cookie"},
		"bad form token": {func() reply {
			return do(t, c, "POST", s.URL()+"/login", formBody("authenticity_token", "x", "login[email]", DefaultEmail, "login[password]", DefaultPassword), formHdr(meta))
		}, "form token wrong"},
	} {
		if r := tc.c(); r.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("%s: status = %d, want 422 (%s)", name, r.StatusCode, tc.msg)
		}
	}
}

func TestWrongTOTPThenRetryWithFreshCSRF(t *testing.T) {
	s := newTestServer(t)
	c := newClient()
	p := newPKCE()
	do(t, c, "GET", authorizeURL(s.URL(), p, "st", true), nil, nil)
	r := do(t, c, "GET", s.URL()+"/login/new", nil, nil)
	meta, form := csrfTokens(t, r.Body)
	r = do(t, c, "POST", s.URL()+"/login", formBody("authenticity_token", form, "login[email]", DefaultEmail, "login[password]", DefaultPassword), formHdr(meta))
	wantStatus(t, r, 303)
	r = do(t, c, "GET", r.Header.Get("Location"), nil, nil)
	meta, form = csrfTokens(t, r.Body)

	bad := "000000"
	for bad == s.CurrentTOTP() || totpValid(s.TOTPSecret(), bad, s.now()) {
		bad = "999999"
	}
	r = do(t, c, "POST", s.URL()+"/sessions/two_factor_authentication", formBody("authenticity_token", form, "type", "authenticator_app", "code", bad, "commit", "Use code"), formHdr(meta))
	wantStatus(t, r, 422)
	for _, want := range []string{"Two factor authentication failed.", "Invalid code, please try again or request a new code."} {
		if !strings.Contains(string(r.Body), want) {
			t.Errorf("422 page lacks %q", want)
		}
	}
	meta2, form2 := csrfTokens(t, r.Body)
	if meta2 == meta || form2 == form {
		t.Error("expected a fresh CSRF token on the 422 page")
	}
	r = do(t, c, "POST", s.URL()+"/sessions/two_factor_authentication", formBody("authenticity_token", form2, "type", "authenticator_app", "code", s.CurrentTOTP(), "commit", "Use code"), formHdr(meta2))
	wantStatus(t, r, 200)
	if got := r.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/vnd.turbo-stream.html") {
		t.Errorf("content type = %q", got)
	}
	loc := reTurbo.FindStringSubmatch(string(r.Body))[1]
	if !strings.Contains(loc, "&amp;") || !strings.HasPrefix(loc, "/oauth/authorize?") || strings.Contains(loc, "prompt") {
		t.Errorf("turbo location = %q", loc)
	}
	if !strings.Contains(string(r.Body), `action="redirect_to"`) {
		t.Errorf("turbo body = %s", r.Body)
	}
}

func TestTOTPAcceptsAdjacentWindowsViaClock(t *testing.T) {
	now := fixedNow
	s := newTestServer(t, WithClock(func() time.Time { return now }))
	code := s.CurrentTOTP()
	now = now.Add(30 * time.Second)
	if !totpValid(s.TOTPSecret(), code, s.now()) {
		t.Fatal("previous window rejected")
	}
	now = now.Add(60 * time.Second)
	if totpValid(s.TOTPSecret(), code, s.now()) {
		t.Fatal("stale window accepted")
	}
}

func TestAuthorizeWhenAlreadyAuthenticated(t *testing.T) {
	s := newTestServer(t)
	c := newClient()
	loginClient(t, s, c)
	p := newPKCE()
	r := do(t, c, "GET", authorizeURL(s.URL(), p, "again", false), nil, nil)
	wantStatus(t, r, 302)
	if loc := r.Header.Get("Location"); !strings.HasPrefix(loc, "com.butterflymx.oauth://oauth?code=") || !strings.HasSuffix(loc, "&state=again") {
		t.Errorf("location = %q", loc)
	}
	// prompt=login forces a new login.
	r = do(t, c, "GET", authorizeURL(s.URL(), p, "again", true), nil, nil)
	if !strings.HasSuffix(r.Header.Get("Location"), "/login/new") {
		t.Errorf("prompt=login location = %q", r.Header.Get("Location"))
	}
}

func TestAuthorizeRejectsBadParams(t *testing.T) {
	s := newTestServer(t)
	for _, q := range []url.Values{
		{"client_id": {"x"}, "redirect_uri": {RedirectURI}, "response_type": {"code"}, "code_challenge": {"c"}, "code_challenge_method": {"S256"}},
		{"client_id": {ClientID}, "redirect_uri": {"https://evil.example"}, "response_type": {"code"}, "code_challenge": {"c"}, "code_challenge_method": {"S256"}},
		{"client_id": {ClientID}, "redirect_uri": {RedirectURI}, "response_type": {"code"}},
	} {
		r := do(t, newClient(), "GET", s.URL()+"/oauth/authorize?"+q.Encode(), nil, nil)
		if r.StatusCode != http.StatusBadRequest {
			t.Errorf("%v: status = %d", q, r.StatusCode)
		}
	}
}

func postToken(t *testing.T, s *Server, kv ...string) reply {
	t.Helper()
	return do(t, newClient(), "POST", s.URL()+"/oauth/token", formBody(kv...), map[string]string{"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})
}

func TestCodeExchangeChecks(t *testing.T) {
	s := newTestServer(t, WithoutMFA())
	getCode := func(p pkce) string {
		c := newClient()
		do(t, c, "GET", authorizeURL(s.URL(), p, "s", true), nil, nil)
		r := do(t, c, "GET", s.URL()+"/login/new", nil, nil)
		meta, form := csrfTokens(t, r.Body)
		r = do(t, c, "POST", s.URL()+"/login", formBody("authenticity_token", form, "login[email]", DefaultEmail, "login[password]", DefaultPassword), formHdr(meta))
		loc := reTurbo.FindStringSubmatch(string(r.Body))[1]
		r = do(t, c, "GET", s.URL()+strings.ReplaceAll(loc, "&amp;", "&"), nil, nil)
		u, _ := url.Parse(r.Header.Get("Location"))
		return u.Query().Get("code")
	}
	p := newPKCE()
	exchange := func(code, verifier, redirect string) reply {
		return postToken(t, s, "grant_type", "authorization_code", "code", code, "code_verifier", verifier, "redirect_uri", redirect, "client_id", ClientID)
	}

	// wrong verifier -> invalid_grant, and the code is burnt
	code := getCode(p)
	r := exchange(code, "wrong-verifier", RedirectURI)
	wantStatus(t, r, 400)
	if r.JSON(t)["error"] != "invalid_grant" {
		t.Errorf("error = %v", r.JSON(t))
	}
	wantStatus(t, exchange(code, p.verifier, RedirectURI), 400)

	// wrong redirect_uri
	code = getCode(p)
	wantStatus(t, exchange(code, p.verifier, "https://evil.example"), 400)

	// single use
	code = getCode(p)
	wantStatus(t, exchange(code, p.verifier, RedirectURI), 200)
	wantStatus(t, exchange(code, p.verifier, RedirectURI), 400)

	// unknown client
	wantStatus(t, postToken(t, s, "grant_type", "authorization_code", "code", "x", "client_id", "nope"), 401)
	// unsupported grant
	r = postToken(t, s, "grant_type", "password", "client_id", ClientID)
	wantStatus(t, r, 400)
	if r.JSON(t)["error"] != "unsupported_grant_type" {
		t.Errorf("error = %v", r.JSON(t))
	}
}

func TestRefreshRotates(t *testing.T) {
	s := newTestServer(t)
	tk := login(t, s)
	refresh := func(rt string) reply {
		return postToken(t, s, "grant_type", "refresh_token", "refresh_token", rt, "client_id", ClientID)
	}
	r := refresh(tk.Refresh)
	wantStatus(t, r, 200)
	next := r.JSON(t)
	if next["refresh_token"] == tk.Refresh || next["access_token"] == tk.Access {
		t.Error("tokens did not rotate")
	}
	// the old refresh token is dead
	r = refresh(tk.Refresh)
	wantStatus(t, r, 400)
	if r.JSON(t)["error"] != "invalid_grant" {
		t.Errorf("error = %v", r.JSON(t))
	}
	// the new one works, then RevokeRefreshTokens kills it
	rt := next["refresh_token"].(string)
	s.RevokeRefreshTokens()
	wantStatus(t, refresh(rt), 400)
	wantStatus(t, refresh("garbage"), 400)
}

func TestRegionsNeedsOAuthToken(t *testing.T) {
	now := fixedNow
	s := newTestServer(t, WithClock(func() time.Time { return now }), WithTokenTTL(time.Hour))
	tk := login(t, s)
	get := func(tok string) reply {
		return do(t, newClient(), "GET", s.URL()+"/api/mobile/regions", nil, map[string]string{"Authorization": "Bearer " + tok})
	}
	r := get(tk.Access)
	wantStatus(t, r, 200)
	if got := r.JSON(t)["regions"].([]any); len(got) != 1 || got[0] != "na" {
		t.Errorf("regions = %v", got)
	}
	if r.Header.Get("ETag") == "" {
		t.Error("expected an ETag")
	}
	wantStatus(t, get(tk.API), 401) // the API token is not an OAuth token
	wantStatus(t, get(""), 401)
	if tk.Raw["expires_in"] != float64(3600) {
		t.Errorf("expires_in = %v", tk.Raw["expires_in"])
	}
	now = now.Add(2 * time.Hour)
	wantStatus(t, get(tk.Access), 401)
}
