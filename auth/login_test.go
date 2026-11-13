package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLoginWith2FA(t *testing.T) {
	f := newFake(t)
	ctx := context.Background()
	res, err := StartLogin(ctx, f.cfg(), testEmail, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if res.Token != nil || res.Challenge == nil {
		t.Fatalf("want challenge, got %+v", res)
	}
	if res.Challenge.Method != "authenticator_app" {
		t.Errorf("method = %q", res.Challenge.Method)
	}
	tok, err := CompleteLogin(ctx, f.cfg(), res.Challenge, testCode)
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "FAKE_ACCESS_TOKEN" || tok.RefreshToken != "FAKE_REFRESH_TOKEN" || tok.IDToken != "FAKE_ID_TOKEN" ||
		tok.APIToken != "FAKE_API_TOKEN" || tok.Region != "na" {
		t.Errorf("unexpected token %v", tok)
	}
	if d := time.Until(tok.Expiry); d < 23*time.Hour || d > 24*time.Hour+time.Minute {
		t.Errorf("expiry in %v", d)
	}
	if tok.APITokenIssuedAt.IsZero() {
		t.Error("APITokenIssuedAt unset")
	}
	if f.exchanges.Load() != 1 || f.denizens.Load() != 1 {
		t.Errorf("exchanges=%d denizens=%d", f.exchanges.Load(), f.denizens.Load())
	}
}

func TestWrongCodeThenSuccessAfterRemarshal(t *testing.T) {
	f := newFake(t)
	ctx := context.Background()
	res, err := StartLogin(ctx, f.cfg(), testEmail, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	c := res.Challenge
	// Round trip through bytes, as a backend would between requests.
	data, err := c.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var c2 MFAChallenge
	if err := c2.UnmarshalBinary(data); err != nil {
		t.Fatal(err)
	}
	stale := c2.csrf
	if _, err := CompleteLogin(ctx, f.cfg(), &c2, "000000"); !errors.Is(err, ErrInvalidMFACode) {
		t.Fatalf("err = %v, want ErrInvalidMFACode", err)
	}
	f.mu.Lock()
	page := f.csrf
	f.mu.Unlock()
	if c2.csrf == stale || c2.csrf != page {
		t.Error("challenge was not updated with the re-rendered page's CSRF token")
	}
	data, err = c2.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var c3 MFAChallenge
	if err := c3.UnmarshalBinary(data); err != nil {
		t.Fatal(err)
	}
	tok, err := CompleteLogin(ctx, f.cfg(), &c3, testCode)
	if err != nil {
		t.Fatal(err)
	}
	if tok.APIToken == "" {
		t.Error("no API token")
	}
}

func TestMFAChallengeVersion(t *testing.T) {
	var c MFAChallenge
	for _, v := range []string{"99", "1", "2"} { // 1 and 2 are the retired Rails-era challenges
		if err := c.UnmarshalBinary([]byte(`{"version":` + v + `}`)); err == nil {
			t.Errorf("want error for version %s", v)
		}
	}
	if err := c.UnmarshalBinary([]byte(`nope`)); err == nil {
		t.Error("want error for garbage")
	}
}

func TestExpiredChallenge(t *testing.T) {
	f := newFake(t)
	ctx := context.Background()
	res, err := StartLogin(ctx, f.cfg(), testEmail, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	before := f.requests.Load()
	res.Challenge.CreatedAt = time.Now().Add(-11 * time.Minute)
	if _, err := CompleteLogin(ctx, f.cfg(), res.Challenge, testCode); !errors.Is(err, ErrMFAExpired) {
		t.Fatalf("err = %v", err)
	}
	if f.requests.Load() != before {
		t.Error("expired challenge must not hit the network")
	}
	// The TTL is configurable.
	old := MFAChallengeTTL
	t.Cleanup(func() { MFAChallengeTTL = old })
	MFAChallengeTTL = time.Nanosecond
	res.Challenge.CreatedAt = time.Now().Add(-time.Second)
	if _, err := CompleteLogin(ctx, f.cfg(), res.Challenge, testCode); !errors.Is(err, ErrMFAExpired) {
		t.Fatalf("err = %v", err)
	}
}

func TestInvalidCredentials(t *testing.T) {
	// A failed sign-in redirects back to the login page, which shows the
	// error; a 200 re-render of the form with the error is read the same way.
	for _, mode := range []string{"badcreds", "badcreds-200"} {
		t.Run(mode, func(t *testing.T) {
			f := newFake(t)
			f.loginMode = mode
			_, err := StartLogin(context.Background(), f.cfg(), testEmail, testPassword)
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// A redirect back to the login page without the known error message (a CSRF
// failure, say) must not be reported as a wrong password.
func TestLoginBounceWithoutErrorIsFlowChanged(t *testing.T) {
	f := newFake(t)
	f.loginMode = "bounce"
	_, err := StartLogin(context.Background(), f.cfg(), testEmail, testPassword)
	if !errors.Is(err, ErrLoginFlowChanged) || errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v", err)
	}
}

func TestUnknownPageIsFlowChanged(t *testing.T) {
	f := newFake(t)
	f.loginMode = "weird"
	_, err := StartLogin(context.Background(), f.cfg(), testEmail, testPassword)
	if !errors.Is(err, ErrLoginFlowChanged) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "CAPTCHA") {
		t.Errorf("error should include the body excerpt: %v", err)
	}
	if strings.Contains(err.Error(), testPassword) || strings.Contains(err.Error(), testEmail) {
		t.Errorf("error leaks credentials: %v", err)
	}
}

func TestStateMismatch(t *testing.T) {
	f := newFake(t)
	ctx := context.Background()
	res, err := StartLogin(ctx, f.cfg(), testEmail, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	f.stateOverride = "attacker-state"
	if _, err := CompleteLogin(ctx, f.cfg(), res.Challenge, testCode); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("err = %v", err)
	}
	if f.exchanges.Load() != 0 {
		t.Error("code must not be exchanged after a state mismatch")
	}
}

func TestNo2FAPaths(t *testing.T) {
	for _, mode := range []string{"redirect"} {
		t.Run(mode, func(t *testing.T) {
			f := newFake(t)
			f.loginMode = mode
			res, err := StartLogin(context.Background(), f.cfg(), testEmail, testPassword)
			if err != nil {
				t.Fatal(err)
			}
			if res.Token == nil || res.Challenge != nil {
				t.Fatalf("want token only: %+v", res)
			}
			if res.Token.APIToken != "FAKE_API_TOKEN" {
				t.Error("no API token")
			}
		})
	}
}

func TestUnsupportedMFAMethod(t *testing.T) {
	c := &MFAChallenge{Method: "carrier-pigeon", CreatedAt: time.Now()}
	if _, err := CompleteLogin(context.Background(), Production, c, "1"); !errors.Is(err, ErrMFAMethodUnsupported) {
		t.Fatalf("err = %v", err)
	}
}

func TestAuthCodeFlow(t *testing.T) {
	f := newFake(t)
	flow := NewAuthCodeFlow(f.cfg())
	s, err := flow.Start()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"code_challenge_method=S256", "prompt=login", "scope=openid+profile", "/oauth/authorize?"} {
		if !strings.Contains(s.URL, want) {
			t.Errorf("URL %q lacks %q", s.URL, want)
		}
	}
	if len(s.Verifier) != 43 || len(s.State) != 43 {
		t.Errorf("verifier/state lengths %d/%d", len(s.Verifier), len(s.State))
	}
	f.challenge = pkceChallenge(s.Verifier)
	redirect := "com.butterflymx.oauth://oauth?code=AUTHCODE&state=" + s.State
	tok, err := flow.Finish(context.Background(), s, redirect)
	if err != nil {
		t.Fatal(err)
	}
	if tok.APIToken == "" {
		t.Error("no API token")
	}
	if _, err := flow.Finish(context.Background(), s, "com.butterflymx.oauth://oauth?code=AUTHCODE&state=other"); !errors.Is(err, ErrStateMismatch) {
		t.Errorf("err = %v", err)
	}
}

func TestBuildingBlocks(t *testing.T) {
	f := newFake(t)
	ctx := context.Background()
	if err := Logout(ctx, f.cfg(), "tok"); err != nil {
		t.Error(err)
	}
	if err := Logout(ctx, f.cfg(), "bad"); err == nil {
		t.Error("want logout error")
	}
	r, err := Regions(ctx, f.cfg(), "x")
	if err != nil || len(r) != 1 || r[0] != "na" {
		t.Errorf("regions = %v, %v", r, err)
	}
}

func TestFlowChangedRedactsEverything(t *testing.T) {
	l := &loginClient{secrets: []string{"p@ssword", "123456"}}
	page := &response{status: 200, body: `<html><body><form action="/x?password=p%40ssword&code=123456"><p>oops</p></form></body></html>`}
	err := l.flowChanged("unexpected redirect /error/p%40ssword/p@ssword", page)
	for _, leak := range []string{"p@ssword", "p%40ssword", "123456"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error leaks %q: %v", leak, err)
		}
	}
	if !strings.Contains(err.Error(), "forms: /x") || !strings.Contains(err.Error(), "oops") {
		t.Errorf("error lost the page description: %v", err)
	}
}

func TestAppRedirectMatchIsExact(t *testing.T) {
	cfg := Production
	for loc, want := range map[string]bool{
		"com.butterflymx.oauth://oauth?code=c&state=s": true,
		"com.butterflymx.oauth://oauth":                true,
		"com.butterflymx.oauth://oauth.evil?code=c":    false,
		"com.butterflymx.oauth://oauth/extra?code=c":   false,
		"com.butterflymx.oauth.evil://oauth?code=c":    false,
		"https://accounts.butterflymx.com/login":       false,
	} {
		if got := cfg.isAppRedirect(loc); got != want {
			t.Errorf("isAppRedirect(%q) = %v, want %v", loc, got, want)
		}
	}
	if _, err := codeFromRedirect(cfg, "com.butterflymx.oauth://oauth.evil?code=c&state=s", "s"); !errors.Is(err, ErrLoginFlowChanged) {
		t.Errorf("codeFromRedirect accepted a look-alike: %v", err)
	}
}

// Credentials must never be sent over a plain-HTTP form action on the
// accounts host, nor to another origin.
func TestSendRefusesOtherOrigins(t *testing.T) {
	cfg := Production
	cfg.AccountsURL = "https://accounts.butterflymx.com"
	l, err := newLoginClient(cfg.withDefaults(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"http://accounts.butterflymx.com/login", "https://evil.example/login"} {
		u, _ := url.Parse(raw)
		if _, err := l.send(context.Background(), http.MethodPost, u, url.Values{"password": {"x"}}); !errors.Is(err, ErrLoginFlowChanged) {
			t.Errorf("send(%s) err = %v", raw, err)
		}
	}
}
