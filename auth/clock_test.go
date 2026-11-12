package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeClock is a manually advanced clock.
type fakeClock struct{ t time.Time }

func newFakeClock() *fakeClock { return &fakeClock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)} }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func TestChallengeAgesViaInjectedClock(t *testing.T) {
	f := newFake(t)
	f.defaultMFA = "sms"
	clk := newFakeClock()
	cfg := f.cfg()
	cfg.Now = clk.now
	ctx := context.Background()

	startC := func() *MFAChallenge {
		t.Helper()
		res, err := StartLogin(ctx, cfg, testEmail, testPassword)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Challenge.CreatedAt.Equal(clk.t) {
			t.Fatalf("CreatedAt = %v, want %v", res.Challenge.CreatedAt, clk.t)
		}
		return res.Challenge
	}

	// Stale challenge: every entry point reports expiry without any request.
	c := startC()
	clk.advance(MFAChallengeTTL + time.Second)
	before := f.requests.Load()
	if _, err := CompleteLogin(ctx, cfg, c, testCode); !errors.Is(err, ErrMFAExpired) {
		t.Errorf("CompleteLogin err = %v", err)
	}
	if err := SwitchMFAMethod(ctx, cfg, c, MFAEmail); !errors.Is(err, ErrMFAExpired) {
		t.Errorf("SwitchMFAMethod err = %v", err)
	}
	if err := ResendMFACode(ctx, cfg, c); !errors.Is(err, ErrMFAExpired) {
		t.Errorf("ResendMFACode err = %v", err)
	}
	if f.requests.Load() != before {
		t.Error("expired challenge must not hit the network")
	}

	// A challenge just inside the TTL still works, and the token times come
	// from the injected clock.
	c = startC()
	clk.advance(MFAChallengeTTL - time.Second)
	if err := ResendMFACode(ctx, cfg, c); err != nil {
		t.Fatalf("ResendMFACode: %v", err)
	}
	tok, err := CompleteLogin(ctx, cfg, c, testCode)
	if err != nil {
		t.Fatal(err)
	}
	if want := clk.t.Add(86400 * time.Second); !tok.Expiry.Equal(want) {
		t.Errorf("Expiry = %v, want %v", tok.Expiry, want)
	}
	if !tok.APITokenIssuedAt.Equal(clk.t) {
		t.Errorf("APITokenIssuedAt = %v, want %v", tok.APITokenIssuedAt, clk.t)
	}
}

func TestChallengeClockSurvivesInProcessAndRoundTrip(t *testing.T) {
	f := newFake(t)
	clk := newFakeClock()
	withClock := f.cfg()
	withClock.Now = clk.now
	ctx := context.Background()

	res, err := StartLogin(ctx, withClock, testEmail, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	clk.advance(MFAChallengeTTL + time.Minute)

	// The in-process challenge remembers its creation clock even when the
	// completing Config has none.
	if _, err := CompleteLogin(ctx, f.cfg(), res.Challenge, testCode); !errors.Is(err, ErrMFAExpired) {
		t.Errorf("in-process err = %v", err)
	}
	// A restored challenge takes the clock of the Config passed in.
	restored := roundTrip(t, res.Challenge)
	if _, err := CompleteLogin(ctx, withClock, restored, testCode); !errors.Is(err, ErrMFAExpired) {
		t.Errorf("restored err = %v", err)
	}
}

func TestExchangeAndRefreshUseConfigClock(t *testing.T) {
	f := newFake(t)
	clk := newFakeClock()
	cfg := f.cfg()
	cfg.Now = clk.now

	tok, err := Refresh(context.Background(), cfg, "REFRESH_OLD")
	if err != nil {
		t.Fatal(err)
	}
	if want := clk.t.Add(86400 * time.Second); !tok.Expiry.Equal(want) {
		t.Errorf("Expiry = %v, want %v", tok.Expiry, want)
	}
}

func TestAuthenticatorRefreshesWhenInjectedClockPassesExpiry(t *testing.T) {
	f := newFake(t)
	clk := newFakeClock()
	cfg := f.cfg()
	cfg.Now = clk.now // Config.Now alone drives the Authenticator
	tok := seedToken()
	tok.Expiry = clk.t.Add(2 * time.Hour)
	a := NewAuthenticator(AuthenticatorConfig{Config: cfg, Store: NewMemoryTokenStore(tok)})
	ctx := context.Background()

	got, err := a.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "ACCESS_OLD" || f.refreshes.Load() != 0 {
		t.Fatalf("unexpected refresh: %v (refreshes %d)", got, f.refreshes.Load())
	}
	clk.advance(2 * time.Hour)
	got, err = a.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "REFRESHED_ACCESS" || f.refreshes.Load() != 1 {
		t.Fatalf("token = %v (refreshes %d)", got, f.refreshes.Load())
	}
	if want := clk.t.Add(86400 * time.Second); !got.Expiry.Equal(want) {
		t.Errorf("Expiry = %v, want %v", got.Expiry, want)
	}
	api, err := a.APIToken(ctx)
	if err != nil || api == "" {
		t.Fatalf("APIToken = %q, %v", api, err)
	}
	cur, _ := a.snapshot(ctx)
	if !cur.APITokenIssuedAt.Equal(clk.t) {
		t.Errorf("APITokenIssuedAt = %v, want %v", cur.APITokenIssuedAt, clk.t)
	}
}

func TestAuthenticatorNowOverridesConfigNow(t *testing.T) {
	f := newFake(t)
	cfgClk, authClk := newFakeClock(), newFakeClock()
	authClk.advance(100 * 24 * time.Hour)
	cfg := f.cfg()
	cfg.Now = cfgClk.now
	tok := seedToken()
	tok.Expiry = cfgClk.t.Add(time.Hour) // valid by Config.Now, long expired by AuthenticatorConfig.Now
	a := NewAuthenticator(AuthenticatorConfig{Config: cfg, Store: NewMemoryTokenStore(tok), Now: authClk.now})
	got, err := a.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "REFRESHED_ACCESS" {
		t.Fatalf("token = %v", got)
	}
	if want := authClk.t.Add(86400 * time.Second); !got.Expiry.Equal(want) {
		t.Errorf("Expiry = %v, want %v", got.Expiry, want)
	}
}
