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
			if !strings.Contains(rq.Body, "email=resident%40example.com") || !strings.Contains(rq.Body, "REDACTED") || rq.Status != 302 {
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
	tok := csrfToken(t, r.Body)
	// A failed sign-in redirects back to the login page, which shows the error once.
	r = do(t, c, "POST", s.URL()+"/login", loginBody(tok, DefaultEmail, "nope"), formHdr())
	wantStatus(t, r, 303)
	if r.Header.Get("Location") != "/login/new" {
		t.Fatalf("location = %q", r.Header.Get("Location"))
	}
	r = do(t, c, "GET", s.URL()+"/login/new", nil, nil)
	wantStatus(t, r, 200)
	body := string(r.Body)
	if !strings.Contains(body, `action="/login"`) || !strings.Contains(body, "Invalid email or password") {
		t.Fatalf("expected the login form with an error:\n%s", body)
	}
	r = do(t, c, "GET", s.URL()+"/login/new", nil, nil)
	if strings.Contains(string(r.Body), "Invalid email or password") {
		t.Error("the error must be shown only once")
	}
}

func TestCSRFIsEnforced(t *testing.T) {
	s := newTestServer(t)
	c := newClient()
	r := do(t, c, "GET", s.URL()+"/login/new", nil, nil)
	tok := csrfToken(t, r.Body)

	for name, tc := range map[string]func() reply{
		"no token": func() reply {
			return do(t, c, "POST", s.URL()+"/login", loginBody("", DefaultEmail, DefaultPassword), formHdr())
		},
		"bad token": func() reply {
			return do(t, c, "POST", s.URL()+"/login", loginBody("bogus", DefaultEmail, DefaultPassword), formHdr())
		},
		"no session": func() reply {
			return do(t, newClient(), "POST", s.URL()+"/login", loginBody(tok, DefaultEmail, DefaultPassword), formHdr())
		},
		"no cookie": func() reply {
			// The token alone is not enough: the cookie must match (double submit).
			h := formHdr()
			cookie := ""
			for _, ck := range c.Jar.Cookies(mustURL(t, s.URL())) {
				if ck.Name == sessionCookie {
					cookie = ck.Name + "=" + ck.Value
				}
			}
			h["Cookie"] = cookie
			return do(t, &http.Client{CheckRedirect: c.CheckRedirect}, "POST", s.URL()+"/login", loginBody(tok, DefaultEmail, DefaultPassword), h)
		},
	} {
		if r := tc(); r.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", name, r.StatusCode)
		}
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestWrongTOTPRerendersThenRetry(t *testing.T) {
	s := newTestServer(t)
	c := newClient()
	p := newPKCE()
	do(t, c, "GET", authorizeURL(s.URL(), p, "st", true), nil, nil)
	r := do(t, c, "GET", s.URL()+"/login/new", nil, nil)
	r = do(t, c, "POST", s.URL()+"/login", loginBody(csrfToken(t, r.Body), DefaultEmail, DefaultPassword), formHdr())
	wantStatus(t, r, 302)
	r = do(t, c, "GET", s.URL()+r.Header.Get("Location"), nil, nil)
	tok := csrfToken(t, r.Body)

	bad := "000000"
	for bad == s.CurrentTOTP() || totpValid(s.TOTPSecret(), bad, s.now()) {
		bad = "999999"
	}
	// A wrong code answers 200 with the challenge page again (as captured).
	r = do(t, c, "POST", s.URL()+"/login/two_factor_authentication", formBody("_csrf_token", tok, "type", "authenticator_app", "code", bad), formHdr())
	wantStatus(t, r, 200)
	if !strings.Contains(string(r.Body), "Invalid verification code") || !strings.Contains(string(r.Body), `action="/login/two_factor_authentication"`) {
		t.Errorf("re-rendered page lacks the error or the form:\n%s", r.Body)
	}
	tok = csrfToken(t, r.Body)
	r = do(t, c, "POST", s.URL()+"/login/two_factor_authentication", formBody("_csrf_token", tok, "type", "authenticator_app", "code", s.CurrentTOTP()), formHdr())
	wantStatus(t, r, 302)
	loc := r.Header.Get("Location")
	if !strings.HasPrefix(loc, "/oauth/authorize?") || strings.Contains(loc, "prompt") {
		t.Errorf("location = %q", loc)
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
	// Already signed in: the "Returning to app" page links to the app.
	cb := appCallback(t, r)
	if cb.Query().Get("code") == "" || cb.Query().Get("state") != "again" {
		t.Errorf("callback = %q", cb)
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
		r = do(t, c, "POST", s.URL()+"/login", loginBody(csrfToken(t, r.Body), DefaultEmail, DefaultPassword), formHdr())
		return appCallback(t, do(t, c, "GET", s.URL()+r.Header.Get("Location"), nil, nil)).Query().Get("code")
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
