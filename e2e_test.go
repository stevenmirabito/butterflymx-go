package butterflymx_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stevenmirabito/butterflymx-go"
	"github.com/stevenmirabito/butterflymx-go/auth"
	"github.com/stevenmirabito/butterflymx-go/butterflymxtest"
)

// fakeClock is a settable clock shared by the fake server and the
// Authenticator.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Now().Truncate(time.Second)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeWorld is a fake server together with the clock it shares with the
// library under test.
type fakeWorld struct {
	*butterflymxtest.Server
	clock *fakeClock
}

// newFakeWorld starts a fake server on a new shared clock.
func newFakeWorld(t *testing.T, opts ...butterflymxtest.Option) *fakeWorld {
	t.Helper()
	clock := newFakeClock()
	srv := butterflymxtest.NewServer(append([]butterflymxtest.Option{butterflymxtest.WithClock(clock.Now)}, opts...)...)
	t.Cleanup(srv.Close)
	return &fakeWorld{Server: srv, clock: clock}
}

func (f *fakeWorld) env() butterflymx.Environment { return butterflymx.LocalEnvironment(f.URL()) }

// authConfig is the environment's auth.Config with the shared clock.
func (f *fakeWorld) authConfig() auth.Config {
	cfg := f.env().AuthConfig()
	cfg.Now = f.clock.Now
	return cfg
}

// e2eLogin runs the interactive login: a wrong code first, then the right one,
// with the challenge serialized in between like a real two-step UI would.
func e2eLogin(t *testing.T, srv *fakeWorld) *auth.Token {
	t.Helper()
	ctx := context.Background()
	cfg := srv.authConfig()
	res, err := auth.StartLogin(ctx, cfg, butterflymxtest.DefaultEmail, butterflymxtest.DefaultPassword)
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	if res.Token != nil || res.Challenge == nil {
		t.Fatalf("expected a 2FA challenge, got %+v", res)
	}
	if res.Challenge.Method != auth.MFAAuthenticatorApp {
		t.Fatalf("method = %q", res.Challenge.Method)
	}
	blob, err := res.Challenge.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var ch auth.MFAChallenge
	if err := ch.UnmarshalBinary(blob); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.CompleteLogin(ctx, cfg, &ch, "000000"); !errors.Is(err, auth.ErrInvalidMFACode) {
		t.Fatalf("wrong code: err = %v, want ErrInvalidMFACode", err)
	}
	// The challenge was updated in place and can be retried.
	blob, err = ch.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var retry auth.MFAChallenge
	if err := retry.UnmarshalBinary(blob); err != nil {
		t.Fatal(err)
	}
	tok, err := auth.CompleteLogin(ctx, cfg, &retry, srv.CurrentTOTP())
	if err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" || tok.APIToken == "" {
		t.Fatalf("incomplete token %v", tok)
	}
	return tok
}

type e2eWorld struct {
	srv   *butterflymxtest.Server
	store *auth.MemoryTokenStore
	a     *auth.Authenticator
	c     *butterflymx.Client
	clock *fakeClock
}

// newE2E starts a fake, logs in through the real login flow, and builds an
// Authenticator-backed client. The server and the Authenticator share a clock.
func newE2E(t *testing.T, relogin func(context.Context) (*auth.Token, error), opts ...butterflymxtest.Option) *e2eWorld {
	t.Helper()
	srv := newFakeWorld(t, opts...)
	clock := srv.clock
	store := auth.NewMemoryTokenStore(e2eLogin(t, srv))
	a := auth.NewAuthenticator(auth.AuthenticatorConfig{Config: srv.authConfig(), Store: store, Relogin: relogin, Now: clock.Now})
	c, err := butterflymx.New(butterflymx.Options{Environment: srv.env(), Auth: a})
	if err != nil {
		t.Fatal(err)
	}
	return &e2eWorld{srv: srv.Server, store: store, a: a, c: c, clock: clock}
}

// authConfig is the auth.Config of the world's fake, on the shared clock.
func (w *e2eWorld) authConfig() auth.Config {
	return (&fakeWorld{Server: w.srv, clock: w.clock}).authConfig()
}

func countRequests(srv *butterflymxtest.Server, method, path string) int {
	n := 0
	for _, r := range srv.Requests() {
		if r.Method == method && r.Path == path && !r.Faulted {
			n++
		}
	}
	return n
}

func vkDoors(t *testing.T, w *e2eWorld) (butterflymx.Tenant, []butterflymx.GlobalID) {
	t.Helper()
	ctx := context.Background()
	tenants, err := w.c.Tenants(ctx)
	if err != nil || len(tenants) != 1 {
		t.Fatalf("Tenants = %v, %v", tenants, err)
	}
	tn := tenants[0]
	if !tn.CanCreateGuestPasses() {
		t.Fatal("tenant cannot create guest passes")
	}
	aps, err := w.c.AccessPoints(ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	var doors []butterflymx.GlobalID
	for _, ap := range aps {
		if ap.SupportsVirtualKeys() {
			doors = append(doors, ap.ID)
		}
	}
	if len(doors) < 2 {
		t.Fatalf("only %d virtual-key doors of %d", len(doors), len(aps))
	}
	return tn, doors
}

func TestE2EGuestPassLifecycle(t *testing.T) {
	ctx := context.Background()
	w := newE2E(t, nil)
	tn, doors := vkDoors(t, w)
	now := w.clock.Now()

	// Custom pass with an email recipient.
	custom, err := w.c.CreateKeychain(ctx, butterflymx.CreateKeychainParams{
		TenantID: tn.ID, AccessPointIDs: doors[:2], Name: "Dinner party",
		Schedule:   butterflymx.CustomSchedule{StartsAt: now.Add(time.Hour), EndsAt: now.Add(5 * time.Hour)},
		Recipients: []butterflymx.Recipient{butterflymx.EmailRecipient("Alice Guest", "alice@example.org")},
	})
	if err != nil {
		t.Fatalf("CreateKeychain custom: %v", err)
	}
	if custom.Kind != butterflymx.KindCustom || len(custom.VirtualKeys) != 1 {
		t.Fatalf("custom = %+v", custom)
	}
	vk := custom.VirtualKeys[0]
	if !vk.PIN.Valid() || len(vk.PIN) != 6 || vk.QRCodeURL == "" || vk.InstructionsURL == "" || vk.Email != "alice@example.org" {
		t.Errorf("custom key incomplete: %+v", vk)
	}

	// Recurring pass with an SMS recipient.
	today := butterflymx.DateOf(now)
	recurring, err := w.c.CreateKeychain(ctx, butterflymx.CreateKeychainParams{
		TenantID: tn.ID, AccessPointIDs: doors[:1], Name: "Dog walker",
		Schedule: butterflymx.RecurringSchedule{
			Weekdays: []butterflymx.Weekday{butterflymx.Monday, butterflymx.Wednesday, butterflymx.Friday},
			From:     butterflymx.TimeOfDay{Hour: 9}, To: butterflymx.TimeOfDay{Hour: 17},
			StartDate: today, EndDate: today.AddDays(60),
		},
		Recipients: []butterflymx.Recipient{butterflymx.SMSRecipient("Bob Walker", "(555) 555-0142")},
	})
	if err != nil {
		t.Fatalf("CreateKeychain recurring: %v", err)
	}
	rvk := recurring.VirtualKeys[0]
	if recurring.Kind != butterflymx.KindRecurring || len(recurring.Weekdays) != 3 ||
		!rvk.PIN.Valid() || rvk.QRCodeURL == "" || rvk.InstructionsURL == "" || rvk.SMSNumber != "+15555550142" {
		t.Errorf("recurring = %+v", recurring)
	}

	// The fake recorded both deliveries.
	var email, sms int
	for _, d := range w.srv.SentDeliveries() {
		switch {
		case d.Channel == "email" && d.To == "alice@example.org" && d.PIN == vk.PIN.Reveal() && d.KeychainID == custom.ID.String():
			email++
		case d.Channel == "sms" && d.To == "+15555550142" && d.PIN == rvk.PIN.Reveal() && d.KeychainID == recurring.ID.String():
			sms++
		}
	}
	if email != 1 || sms != 1 {
		t.Errorf("deliveries: email=%d sms=%d in %+v", email, sms, w.srv.SentDeliveries())
	}

	// Both show up in the active list.
	active, err := w.c.Keychains(ctx, tn.ID, butterflymx.KeychainFilter{Status: butterflymx.StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	ids := func(ks []butterflymx.Keychain) []butterflymx.ID {
		var out []butterflymx.ID
		for _, k := range ks {
			out = append(out, k.ID)
		}
		return out
	}
	if !slices.Contains(ids(active), custom.ID) || !slices.Contains(ids(active), recurring.ID) {
		t.Fatalf("active list lacks the new passes: %v", ids(active))
	}

	// Add a key, revoke it, delete the pass.
	added, err := w.c.AddVirtualKeys(ctx, custom.ID, butterflymx.EmailRecipient("Carol Guest", "carol@example.org"))
	if err != nil || len(added) != 1 || !added[0].PIN.Valid() {
		t.Fatalf("AddVirtualKeys = %+v, %v", added, err)
	}
	if err := w.c.RevokeVirtualKey(ctx, custom.ID, added[0].ID); err != nil {
		t.Fatalf("RevokeVirtualKey: %v", err)
	}
	got, err := w.c.Keychain(ctx, custom.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.VirtualKeys) != 1 || got.VirtualKeys[0].ID != vk.ID {
		t.Errorf("after revoke, keys = %+v", got.VirtualKeys)
	}
	if err := w.c.DeleteKeychain(ctx, custom.ID); err != nil {
		t.Fatalf("DeleteKeychain: %v", err)
	}
	active, err = w.c.Keychains(ctx, tn.ID, butterflymx.KeychainFilter{Status: butterflymx.StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(ids(active), custom.ID) {
		t.Error("deleted pass is still active")
	}
	// The fake removes deleted passes outright, so they are in neither list.
	// The expired listing is the seeded history, which spans several pages.
	expired, err := w.c.Keychains(ctx, tn.ID, butterflymx.KeychainFilter{Status: butterflymx.StatusExpired})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(ids(expired), custom.ID) {
		t.Error("deleted pass is in the expired listing")
	}
	if want := len(w.srv.Seed().ExpiredKeychainIDs); len(expired) != want || want <= 20 {
		t.Errorf("expired listing has %d passes, want the %d seeded (more than one page)", len(expired), want)
	}
	if _, err := w.c.Keychain(ctx, custom.ID); !errors.Is(err, butterflymx.ErrNotFound) {
		t.Errorf("Keychain after delete: %v, want ErrNotFound", err)
	}
}

func TestE2EDeliveryPass(t *testing.T) {
	ctx := context.Background()
	w := newE2E(t, nil)
	tn, _ := vkDoors(t, w)

	dp, err := w.c.CreateDeliveryPass(ctx, butterflymx.DeliveryPassParams{TenantID: tn.ID, Name: "Groceries"})
	if err != nil {
		t.Fatal(err)
	}
	if dp.Kind != butterflymx.KindDeliveryPass || dp.Name != "Groceries" || len(dp.VirtualKeys) != 1 || !dp.VirtualKeys[0].PIN.Valid() {
		t.Fatalf("pass = %+v", dp)
	}
	if n := len(w.srv.SentDeliveries()); n != 0 {
		t.Errorf("delivery pass sent %d messages", n)
	}

	renamed, err := w.c.UpdateDeliveryPass(ctx, dp.ID, butterflymx.DeliveryPassUpdate{Name: new("Takeout")})
	if err != nil || renamed.Name != "Takeout" {
		t.Fatalf("rename = %+v, %v", renamed, err)
	}
	extended, err := w.c.ExtendDeliveryPass(ctx, dp.ID, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if want := renamed.EndsAt.Add(48 * time.Hour); !extended.EndsAt.Equal(want) || extended.Name != "Takeout" {
		t.Errorf("extended = %v %q, want %v", extended.EndsAt, extended.Name, want)
	}
	if err := w.c.DeleteKeychain(ctx, dp.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.c.Keychain(ctx, dp.ID); !errors.Is(err, butterflymx.ErrNotFound) {
		t.Errorf("Keychain after delete: %v, want ErrNotFound", err)
	}
}

func TestE2EUnlockAppearsInDoorReleases(t *testing.T) {
	ctx := context.Background()
	w := newE2E(t, nil)
	tn, doors := vkDoors(t, w)

	count := func() int {
		n := 0
		for rel, err := range w.c.DoorReleases(ctx, tn.ID) {
			if err != nil {
				t.Fatal(err)
			}
			if rel.AccessPoint.ID == doors[0] {
				n++
			}
		}
		return n
	}
	before := count()
	reqID, err := w.c.Unlock(ctx, tn.ID, doors[0])
	if err != nil || reqID == "" {
		t.Fatalf("Unlock = %q, %v", reqID, err)
	}
	if u := w.srv.Unlocks(); len(u) != 1 || u[0].RequestID != reqID || u[0].Source != "mobile_app" {
		t.Errorf("unlocks = %+v", u)
	}
	if after := count(); after != before+1 {
		t.Errorf("door releases for the door: %d -> %d, want +1", before, after)
	}
}

func TestE2EAPITokenRevokedMidFlow(t *testing.T) {
	ctx := context.Background()
	w := newE2E(t, nil)
	if _, err := w.c.Tenants(ctx); err != nil {
		t.Fatal(err)
	}
	logins := countRequests(w.srv, "POST", "/denizen/v1/login")
	if logins != 1 {
		t.Fatalf("logins after StartLogin flow = %d, want 1", logins)
	}
	w.srv.RevokeAPITokens()
	if _, err := w.c.Tenants(ctx); err != nil {
		t.Fatalf("Tenants after revoke: %v", err)
	}
	if n := countRequests(w.srv, "POST", "/denizen/v1/login") - logins; n != 1 {
		t.Errorf("denizen logins after revoke = %d, want exactly 1", n)
	}
	if n := countRequests(w.srv, "POST", "/oauth/token"); n != 1 {
		t.Errorf("oauth token calls = %d, want 1 (the initial code exchange only)", n)
	}
	// The store holds the new API token.
	st, _ := w.store.Load(ctx)
	if st.APIToken == "" {
		t.Error("store lost the API token")
	}
	if _, err := w.c.Tenants(ctx); err != nil {
		t.Fatal(err)
	}
	if n := countRequests(w.srv, "POST", "/denizen/v1/login") - logins; n != 1 {
		t.Errorf("a further call logged in again (%d)", n)
	}
}

func TestE2EOAuthExpiryRefreshRotates(t *testing.T) {
	ctx := context.Background()
	w := newE2E(t, nil, butterflymxtest.WithTokenTTL(10*time.Minute))
	before, _ := w.store.Load(ctx)

	w.clock.Advance(11 * time.Minute) // the OAuth access token is now expired
	w.srv.RevokeAPITokens()           // and the API token is rejected, forcing a new exchange
	if _, err := w.c.Tenants(ctx); err != nil {
		t.Fatalf("Tenants: %v", err)
	}
	after, _ := w.store.Load(ctx)
	if after.RefreshToken == before.RefreshToken || after.AccessToken == before.AccessToken || after.APIToken == before.APIToken {
		t.Errorf("tokens did not all rotate: %v -> %v", before, after)
	}
	if n := countRequests(w.srv, "POST", "/oauth/token"); n != 2 {
		t.Errorf("oauth token calls = %d, want 2 (exchange + one refresh)", n)
	}
	if !after.Expiry.After(w.clock.Now()) {
		t.Errorf("new expiry %v is not after the clock %v", after.Expiry, w.clock.Now())
	}
	// The old refresh token is dead.
	if _, err := auth.Refresh(ctx, w.authConfig(), before.RefreshToken); !errors.Is(err, auth.ErrReauthRequired) {
		t.Errorf("old refresh token still works: %v", err)
	}
}

func TestE2ERefreshRevokedNeedsReauth(t *testing.T) {
	ctx := context.Background()
	w := newE2E(t, nil, butterflymxtest.WithTokenTTL(10*time.Minute))
	w.clock.Advance(11 * time.Minute)
	w.srv.RevokeAPITokens()
	w.srv.RevokeRefreshTokens()
	_, err := w.c.Tenants(ctx)
	if !errors.Is(err, auth.ErrReauthRequired) {
		t.Fatalf("err = %v, want auth.ErrReauthRequired", err)
	}
}

func TestE2ERefreshRevokedRelogin(t *testing.T) {
	ctx := context.Background()
	var relogins atomic.Int32
	var world *e2eWorld
	relogin := func(ctx context.Context) (*auth.Token, error) {
		relogins.Add(1)
		res, err := auth.StartLogin(ctx, world.authConfig(), butterflymxtest.DefaultEmail, butterflymxtest.DefaultPassword)
		if err != nil {
			return nil, err
		}
		return auth.CompleteLogin(ctx, world.authConfig(), res.Challenge, world.srv.CurrentTOTP())
	}
	w := newE2E(t, relogin, butterflymxtest.WithTokenTTL(10*time.Minute))
	world = w
	before, _ := w.store.Load(ctx)

	w.clock.Advance(11 * time.Minute)
	w.srv.RevokeAPITokens()
	w.srv.RevokeRefreshTokens()
	if _, err := w.c.Tenants(ctx); err != nil {
		t.Fatalf("Tenants with Relogin: %v", err)
	}
	if relogins.Load() != 1 {
		t.Errorf("Relogin called %d times", relogins.Load())
	}
	after, _ := w.store.Load(ctx)
	if after.RefreshToken == before.RefreshToken || after.APIToken == "" {
		t.Errorf("token not replaced: %v", after)
	}
}

func TestE2EConcurrentRevokedToken(t *testing.T) {
	ctx := context.Background()
	w := newE2E(t, nil)
	if _, err := w.c.Tenants(ctx); err != nil {
		t.Fatal(err)
	}
	logins := countRequests(w.srv, "POST", "/denizen/v1/login")
	w.srv.RevokeAPITokens()

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	start := make(chan struct{})
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ts, err := w.c.Tenants(ctx)
			if err == nil && len(ts) != 1 {
				err = errors.New("unexpected tenant count")
			}
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("Tenants: %v", err)
		}
	}
	if got := countRequests(w.srv, "POST", "/denizen/v1/login") - logins; got != 1 {
		t.Errorf("denizen logins = %d, want exactly 1", got)
	}
}
