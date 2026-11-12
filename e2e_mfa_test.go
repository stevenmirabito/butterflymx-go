package butterflymx_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stevenmirabito/butterflymx-go"
	"github.com/stevenmirabito/butterflymx-go/auth"
	"github.com/stevenmirabito/butterflymx-go/butterflymxtest"
)

const mfaChallengePath = "/sessions/two_factor_authentication/new"

// mfaServer starts a fake with a clock shared with the Authenticator.
func mfaServer(t *testing.T, opts ...butterflymxtest.Option) *fakeWorld {
	t.Helper()
	return newFakeWorld(t, opts...)
}

// reload round-trips a challenge through MarshalBinary and UnmarshalBinary, as
// a web backend does between the requests of a login. The returned challenge
// is the only one the caller may use afterwards.
func reload(t *testing.T, c *auth.MFAChallenge) *auth.MFAChallenge {
	t.Helper()
	blob, err := c.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	var out auth.MFAChallenge
	if err := out.UnmarshalBinary(blob); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	return &out
}

// startMFA runs StartLogin and returns the reloaded challenge.
func startMFA(t *testing.T, srv *fakeWorld, opts ...auth.LoginOption) *auth.MFAChallenge {
	t.Helper()
	res, err := auth.StartLogin(context.Background(), srv.authConfig(),
		butterflymxtest.DefaultEmail, butterflymxtest.DefaultPassword, opts...)
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	if res.Token != nil || res.Challenge == nil {
		t.Fatalf("expected a 2FA challenge, got %+v", res)
	}
	return reload(t, res.Challenge)
}

// finishMFA submits code, reloading the challenge first, and checks the token.
func finishMFA(t *testing.T, srv *fakeWorld, c *auth.MFAChallenge, code string) *auth.Token {
	t.Helper()
	tok, err := auth.CompleteLogin(context.Background(), srv.authConfig(), reload(t, c), code)
	if err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" || tok.APIToken == "" {
		t.Fatalf("incomplete token %v", tok)
	}
	return tok
}

func wantMethod(t *testing.T, c *auth.MFAChallenge, method auth.MFAMethod) {
	t.Helper()
	if c.Method != method {
		t.Fatalf("challenge method = %q, want %q", c.Method, method)
	}
}

// useToken builds an Authenticator-backed client from a login's token.
func useToken(t *testing.T, srv *fakeWorld, tok *auth.Token) *e2eWorld {
	t.Helper()
	store := auth.NewMemoryTokenStore(tok)
	a := auth.NewAuthenticator(auth.AuthenticatorConfig{Config: srv.authConfig(), Store: store, Now: srv.clock.Now})
	c, err := butterflymx.New(butterflymx.Options{Environment: srv.env(), Auth: a})
	if err != nil {
		t.Fatal(err)
	}
	return &e2eWorld{srv: srv.Server, store: store, a: a, c: c, clock: srv.clock}
}

func mustTenants(t *testing.T, w *e2eWorld) {
	t.Helper()
	tenants, err := w.c.Tenants(context.Background())
	if err != nil || len(tenants) != 1 {
		t.Fatalf("Tenants = %v, %v", tenants, err)
	}
}

func deliveriesOf(srv *fakeWorld, method string) []butterflymxtest.MFADelivery {
	var out []butterflymxtest.MFADelivery
	for _, d := range srv.MFADeliveries() {
		if d.Method == method {
			out = append(out, d)
		}
	}
	return out
}

func TestE2EMFASMSLogin(t *testing.T) {
	// The real server sends a code when the challenge page is loaded, which
	// is the fake's default. The send-on-GET=false variant keeps the client
	// honest: it must not depend on that behavior.
	for _, tc := range []struct {
		name       string
		sendOnGET  bool
		wantAtOpen int
	}{
		{"code sent when the challenge page loads", true, 1},
		{"code sent only on resend", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			srv := mfaServer(t, butterflymxtest.WithLastMFAMethod("sms"), butterflymxtest.WithMFASendOnGET(tc.sendOnGET))
			cfg := srv.authConfig()

			ch := startMFA(t, srv)
			wantMethod(t, ch, auth.MFASMS)
			if ch.Destination != "******0100" || !ch.CanResend() {
				t.Fatalf("challenge = %v (destination %q, can resend %v)", ch, ch.Destination, ch.CanResend())
			}
			if n := len(srv.MFADeliveries()); n != tc.wantAtOpen {
				t.Fatalf("%d codes sent by StartLogin, want %d", n, tc.wantAtOpen)
			}

			// A wrong code keeps the challenge usable, also after a reload.
			if _, err := auth.CompleteLogin(ctx, cfg, ch, "000000"); !errors.Is(err, auth.ErrInvalidMFACode) {
				t.Fatalf("wrong code: err = %v, want ErrInvalidMFACode", err)
			}
			ch = reload(t, ch)
			wantMethod(t, ch, auth.MFASMS)

			if err := auth.ResendMFACode(ctx, cfg, ch); err != nil {
				t.Fatalf("ResendMFACode: %v", err)
			}
			ch = reload(t, ch)
			sent := deliveriesOf(srv, "sms")
			if len(sent) != tc.wantAtOpen+1 {
				t.Fatalf("sms deliveries = %d, want %d", len(sent), tc.wantAtOpen+1)
			}
			if last := sent[len(sent)-1]; !last.Resend || last.Trigger != "resend" || last.Destination != "******0100" {
				t.Errorf("resend delivery = %+v", last)
			}

			code := srv.LastMFACode("sms")
			if len(code) != 6 {
				t.Fatalf("LastMFACode = %q", code)
			}
			tok := finishMFA(t, srv, ch, code)

			w := useToken(t, srv, tok)
			mustTenants(t, w)
		})
	}
}

func TestE2EMFAEmailShortcut(t *testing.T) {
	srv := mfaServer(t) // the server's default method is authenticator_app

	ch := startMFA(t, srv, auth.WithMFAMethod(auth.MFAEmail))
	wantMethod(t, ch, auth.MFAEmail)
	if ch.Destination != "" || !ch.CanResend() {
		t.Errorf("email challenge: destination %q, can resend %v", ch.Destination, ch.CanResend())
	}

	// The shortcut goes straight to the picker: the default challenge page,
	// which could itself send a text or an email, was never loaded.
	for _, r := range srv.Requests() {
		if r.Method == http.MethodGet && r.Path == mfaChallengePath && r.Query.Get("type") == "authenticator_app" {
			t.Errorf("the default challenge page was fetched: %+v", r)
		}
	}
	if n := countRequests(srv.Server, "GET", "/sessions/two_factor_authentication"); n != 1 {
		t.Errorf("method picker fetched %d times, want 1", n)
	}
	got := srv.MFADeliveries()
	if len(got) != 1 || got[0].Method != "email" || got[0].Destination != butterflymxtest.DefaultEmail || got[0].Trigger != "picker" {
		t.Fatalf("deliveries = %+v, want exactly one email sent from the picker", got)
	}

	tok := finishMFA(t, srv, ch, srv.LastMFACode("email"))
	mustTenants(t, useToken(t, srv, tok))
}

func TestE2EMFASwitchMethods(t *testing.T) {
	ctx := context.Background()
	srv := mfaServer(t, butterflymxtest.WithLastMFAMethod("sms"))
	cfg := srv.authConfig()

	ch := startMFA(t, srv)
	wantMethod(t, ch, auth.MFASMS)
	smsCode := srv.LastMFACode("sms")

	if err := auth.SwitchMFAMethod(ctx, cfg, ch, auth.MFAEmail); err != nil {
		t.Fatalf("switch to email: %v", err)
	}
	ch = reload(t, ch)
	wantMethod(t, ch, auth.MFAEmail)
	if ch.Destination != "" || !ch.CanResend() {
		t.Errorf("after switching to email: destination %q, can resend %v", ch.Destination, ch.CanResend())
	}
	if n := len(deliveriesOf(srv, "email")); n != 1 {
		t.Fatalf("email deliveries = %d, want 1", n)
	}
	// The email code is not accepted as an sms code and vice versa.
	if _, err := auth.CompleteLogin(ctx, cfg, ch, smsCode); smsCode != srv.LastMFACode("email") && !errors.Is(err, auth.ErrInvalidMFACode) {
		t.Fatalf("sms code on an email challenge: err = %v, want ErrInvalidMFACode", err)
	}
	ch = reload(t, ch)

	if err := auth.SwitchMFAMethod(ctx, cfg, ch, auth.MFAAuthenticatorApp); err != nil {
		t.Fatalf("switch to authenticator_app: %v", err)
	}
	ch = reload(t, ch)
	wantMethod(t, ch, auth.MFAAuthenticatorApp)
	if ch.Destination != "" || ch.CanResend() {
		t.Errorf("authenticator challenge: destination %q, can resend %v", ch.Destination, ch.CanResend())
	}
	if err := auth.ResendMFACode(ctx, cfg, ch); !errors.Is(err, auth.ErrMFAResendUnsupported) {
		t.Errorf("resend on authenticator_app: err = %v, want ErrMFAResendUnsupported", err)
	}
	ch = reload(t, ch)
	if n := len(srv.MFADeliveries()); n != 2 {
		t.Errorf("%d codes sent in total, want 2 (sms on open, email on switch)", n)
	}

	tok := finishMFA(t, srv, ch, srv.CurrentTOTP())
	mustTenants(t, useToken(t, srv, tok))
}

func TestE2EMFALastUsedMethodIsRemembered(t *testing.T) {
	srv := mfaServer(t) // starts at authenticator_app
	ctx := context.Background()
	cfg := srv.authConfig()

	if ch := startMFA(t, srv); ch.Method != auth.MFAAuthenticatorApp {
		t.Fatalf("first default method = %q", ch.Method)
	}

	// Log in by SMS (asked for explicitly) ...
	ch := startMFA(t, srv, auth.WithMFAMethod(auth.MFASMS))
	wantMethod(t, ch, auth.MFASMS)
	finishMFA(t, srv, ch, srv.LastMFACode("sms"))

	// ... and the next login is offered sms by the server.
	ch = startMFA(t, srv)
	wantMethod(t, ch, auth.MFASMS)
	if ch.Destination != "******0100" {
		t.Errorf("destination = %q", ch.Destination)
	}

	// Switching to the app and finishing there moves the default back.
	if err := auth.SwitchMFAMethod(ctx, cfg, ch, auth.MFAAuthenticatorApp); err != nil {
		t.Fatal(err)
	}
	finishMFA(t, srv, ch, srv.CurrentTOTP())
	wantMethod(t, startMFA(t, srv), auth.MFAAuthenticatorApp)
}

func TestE2EMFAResendKeepsEarlierCodes(t *testing.T) {
	ctx := context.Background()
	srv := mfaServer(t, butterflymxtest.WithLastMFAMethod("sms"), butterflymxtest.WithMFASendOnGET(false))
	cfg := srv.authConfig()

	ch := startMFA(t, srv)
	if n := len(srv.MFADeliveries()); n != 0 {
		t.Fatalf("%d codes sent before any resend", n)
	}
	for range 2 {
		if err := auth.ResendMFACode(ctx, cfg, ch); err != nil {
			t.Fatalf("ResendMFACode: %v", err)
		}
		ch = reload(t, ch)
	}
	sent := srv.MFADeliveries()
	if len(sent) != 2 {
		t.Fatalf("deliveries = %+v, want 2", sent)
	}
	// The first code still works after the second was sent.
	tok := finishMFA(t, srv, ch, sent[0].Code)
	mustTenants(t, useToken(t, srv, tok))
}

func TestE2EMFAChallengeExpiry(t *testing.T) {
	ctx := context.Background()
	srv := mfaServer(t, butterflymxtest.WithLastMFAMethod("sms"))
	cfg := srv.authConfig()

	// The challenge's age is measured on auth.Config.Now, which srv.authConfig
	// sets to the clock shared with the fake: advancing it ages the challenge.
	ch := startMFA(t, srv)
	srv.clock.Advance(auth.MFAChallengeTTL + time.Second)
	ch = reload(t, ch)
	if _, err := auth.CompleteLogin(ctx, cfg, ch, srv.LastMFACode("sms")); !errors.Is(err, auth.ErrMFAExpired) {
		t.Errorf("CompleteLogin: err = %v, want ErrMFAExpired", err)
	}
	if err := auth.SwitchMFAMethod(ctx, cfg, ch, auth.MFAEmail); !errors.Is(err, auth.ErrMFAExpired) {
		t.Errorf("SwitchMFAMethod: err = %v, want ErrMFAExpired", err)
	}
	if err := auth.ResendMFACode(ctx, cfg, ch); !errors.Is(err, auth.ErrMFAExpired) {
		t.Errorf("ResendMFACode: err = %v, want ErrMFAExpired", err)
	}

	// A fresh challenge is accepted.
	fresh := startMFA(t, srv)
	finishMFA(t, srv, fresh, srv.LastMFACode("sms"))
}

func TestE2EMFACodeExpiresOnServer(t *testing.T) {
	ctx := context.Background()
	srv := mfaServer(t, butterflymxtest.WithLastMFAMethod("sms"))
	// This test ages the server's codes, not the client's challenge (which
	// the shared clock would expire after MFAChallengeTTL), so the client
	// keeps the wall clock; the challenge was created at about that time.
	cfg := srv.authConfig()
	cfg.Now = nil

	ch := startMFA(t, srv)
	stale := srv.LastMFACode("sms")
	srv.clock.Advance(9 * time.Minute)
	if err := auth.ResendMFACode(ctx, cfg, ch); err != nil {
		t.Fatal(err)
	}
	ch = reload(t, ch)
	fresh := srv.LastMFACode("sms")
	srv.clock.Advance(90 * time.Second) // the first code is now 10m30s old, the resent one 90s

	if stale != fresh {
		if _, err := auth.CompleteLogin(ctx, cfg, ch, stale); !errors.Is(err, auth.ErrInvalidMFACode) {
			t.Fatalf("expired code: err = %v, want ErrInvalidMFACode", err)
		}
		ch = reload(t, ch)
	}
	if _, err := auth.CompleteLogin(ctx, cfg, reload(t, ch), fresh); err != nil {
		t.Fatalf("CompleteLogin with the resent code: %v", err)
	}
}

func TestE2EGuestPassAfterSMSLogin(t *testing.T) {
	ctx := context.Background()
	srv := mfaServer(t, butterflymxtest.WithLastMFAMethod("sms"))

	ch := startMFA(t, srv)
	w := useToken(t, srv, finishMFA(t, srv, ch, srv.LastMFACode("sms")))

	tn, doors := vkDoors(t, w)
	now := srv.clock.Now()
	pass, err := w.c.CreateKeychain(ctx, butterflymx.CreateKeychainParams{
		TenantID: tn.ID, AccessPointIDs: doors[:1], Name: "After SMS login",
		Schedule:   butterflymx.CustomSchedule{StartsAt: now.Add(time.Hour), EndsAt: now.Add(3 * time.Hour)},
		Recipients: []butterflymx.Recipient{butterflymx.EmailRecipient("Alice Guest", "alice@example.org")},
	})
	if err != nil {
		t.Fatalf("CreateKeychain: %v", err)
	}
	if len(pass.VirtualKeys) != 1 || !pass.VirtualKeys[0].PIN.Valid() {
		t.Fatalf("pass = %+v", pass)
	}
	if n := len(w.srv.SentDeliveries()); n != 1 {
		t.Errorf("guest deliveries = %d, want 1", n)
	}
	// The login itself used no email 2FA code.
	if n := len(deliveriesOf(srv, "email")); n != 0 {
		t.Errorf("email 2FA codes = %d, want 0", n)
	}
}
