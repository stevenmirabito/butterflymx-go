package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func seedToken() *Token {
	return &Token{
		AccessToken: "ACCESS_OLD", RefreshToken: "REFRESH_OLD", IDToken: "ID_OLD",
		Expiry: time.Now().Add(time.Hour), Region: "na",
	}
}

func TestRefreshRotation(t *testing.T) {
	for _, mode := range []string{"rotate", "norotate"} {
		t.Run(mode, func(t *testing.T) {
			f := newFake(t)
			f.refreshMode = mode
			tok, err := Refresh(context.Background(), f.cfg(), "REFRESH_OLD")
			if err != nil {
				t.Fatal(err)
			}
			want := "ROTATED_REFRESH"
			if mode == "norotate" {
				want = "REFRESH_OLD"
			}
			if tok.RefreshToken != want || tok.AccessToken != "REFRESHED_ACCESS" {
				t.Errorf("token = %v (refresh %q)", tok, tok.RefreshToken)
			}
			if got := f.lastRefreshToken.Load(); got != "REFRESH_OLD" {
				t.Errorf("sent refresh token %v", got)
			}
		})
	}
}

func TestRefreshInvalidGrant(t *testing.T) {
	f := newFake(t)
	f.refreshMode = "invalid_grant"
	if _, err := Refresh(context.Background(), f.cfg(), "x"); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("err = %v", err)
	}
}

func expiredStore() *MemoryTokenStore {
	tok := seedToken()
	tok.Expiry = time.Now().Add(-time.Hour)
	return NewMemoryTokenStore(tok)
}

func TestAuthenticatorRefreshesThenExchanges(t *testing.T) {
	f := newFake(t)
	store := expiredStore()
	a := NewAuthenticator(AuthenticatorConfig{Config: f.cfg(), Store: store})
	api, err := a.APIToken(context.Background())
	if err != nil || api != "FAKE_API_TOKEN" {
		t.Fatalf("api = %q, %v", api, err)
	}
	if got := f.lastDenizenAccess.Load(); got != "REFRESHED_ACCESS" {
		t.Errorf("denizen used access token %v", got)
	}
	stored, _ := store.Load(context.Background())
	if stored.RefreshToken != "ROTATED_REFRESH" || stored.APIToken != "FAKE_API_TOKEN" {
		t.Errorf("stored = %v", stored)
	}
	if f.refreshes.Load() != 1 {
		t.Errorf("refreshes = %d", f.refreshes.Load())
	}
}

func TestAuthenticatorCustomClock(t *testing.T) {
	f := newFake(t)
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	tok := seedToken()
	tok.Expiry = now.Add(30 * time.Second) // < 60s left
	a := NewAuthenticator(AuthenticatorConfig{Config: f.cfg(), Store: NewMemoryTokenStore(tok), Now: func() time.Time { return now }})
	got, err := a.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "REFRESHED_ACCESS" || got.Expiry.Sub(now) < 23*time.Hour {
		t.Errorf("token = %v", got)
	}
}

func TestAuthenticatorInvalidGrant(t *testing.T) {
	f := newFake(t)
	f.refreshMode = "invalid_grant"
	a := NewAuthenticator(AuthenticatorConfig{Config: f.cfg(), Store: expiredStore()})
	if _, err := a.APIToken(context.Background()); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("err = %v", err)
	}

	var calls int
	store := expiredStore()
	a = NewAuthenticator(AuthenticatorConfig{
		Config: f.cfg(), Store: store,
		Relogin: func(context.Context) (*Token, error) {
			calls++
			return &Token{AccessToken: "RELOGIN_ACCESS", RefreshToken: "RELOGIN_REFRESH", Expiry: time.Now().Add(time.Hour), Region: "na"}, nil
		},
	})
	api, err := a.APIToken(context.Background())
	if err != nil || api == "" || calls != 1 {
		t.Fatalf("api=%q err=%v calls=%d", api, err, calls)
	}
	if got := f.lastDenizenAccess.Load(); got != "RELOGIN_ACCESS" {
		t.Errorf("denizen used %v", got)
	}
	stored, _ := store.Load(context.Background())
	if stored.RefreshToken != "RELOGIN_REFRESH" {
		t.Errorf("stored = %v", stored)
	}
}

func TestAuthenticatorEmptyStore(t *testing.T) {
	a := NewAuthenticator(AuthenticatorConfig{Config: newFake(t).cfg()})
	if _, err := a.APIToken(context.Background()); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("err = %v", err)
	}
}

func TestAuthenticatorConcurrentSingleExchange(t *testing.T) {
	f := newFake(t)
	f.denizenDelay = 30 * time.Millisecond
	a := NewAuthenticator(AuthenticatorConfig{Config: f.cfg(), Store: NewMemoryTokenStore(seedToken())})
	var wg sync.WaitGroup
	results := make([]string, 50)
	errs := make([]error, 50)
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = a.APIToken(context.Background())
		}()
	}
	wg.Wait()
	for i := range results {
		if errs[i] != nil || results[i] != "FAKE_API_TOKEN" {
			t.Fatalf("call %d: %q, %v", i, results[i], errs[i])
		}
	}
	if f.denizens.Load() != 1 {
		t.Errorf("denizen exchanges = %d, want 1", f.denizens.Load())
	}
}

func TestAuthenticatorConcurrentSingleRefresh(t *testing.T) {
	f := newFake(t)
	f.denizenDelay = 20 * time.Millisecond
	a := NewAuthenticator(AuthenticatorConfig{Config: f.cfg(), Store: expiredStore()})
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := a.APIToken(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if f.refreshes.Load() != 1 || f.denizens.Load() != 1 {
		t.Errorf("refreshes=%d denizens=%d", f.refreshes.Load(), f.denizens.Load())
	}
}

func TestDenizen401ForcesRefreshAndRetries(t *testing.T) {
	f := newFake(t)
	f.denizenStatus = []int{401}
	a := NewAuthenticator(AuthenticatorConfig{Config: f.cfg(), Store: NewMemoryTokenStore(seedToken())})
	api, err := a.APIToken(context.Background())
	if err != nil || api != "FAKE_API_TOKEN" {
		t.Fatalf("api=%q err=%v", api, err)
	}
	if f.refreshes.Load() != 1 || f.denizens.Load() != 2 {
		t.Errorf("refreshes=%d denizens=%d", f.refreshes.Load(), f.denizens.Load())
	}
	// A second 401 is final.
	f2 := newFake(t)
	f2.denizenStatus = []int{401, 401, 401}
	a = NewAuthenticator(AuthenticatorConfig{Config: f2.cfg(), Store: NewMemoryTokenStore(seedToken())})
	if _, err := a.APIToken(context.Background()); !isStatus(err, 401) {
		t.Fatalf("err = %v", err)
	}
	if f2.refreshes.Load() != 1 {
		t.Errorf("refreshes = %d, want exactly one forced refresh", f2.refreshes.Load())
	}
}

func TestSharedStoreCASConflictRecovery(t *testing.T) {
	f := newFake(t)
	f.apiTokens = true
	store := NewMemoryTokenStore(seedToken())
	ctx := context.Background()
	a := NewAuthenticator(AuthenticatorConfig{Config: f.cfg(), Store: store})
	b := NewAuthenticator(AuthenticatorConfig{Config: f.cfg(), Store: store})
	if _, err := b.Token(ctx); err != nil { // b caches the token without an API token
		t.Fatal(err)
	}
	ta, err := a.APIToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tb, err := b.APIToken(ctx) // exchanges, loses the CAS, adopts a's token
	if err != nil {
		t.Fatal(err)
	}
	if ta != tb {
		t.Errorf("a=%q b=%q, want the same token", ta, tb)
	}
	if f.denizens.Load() != 2 {
		t.Errorf("denizens = %d, want 2 (b raced and lost)", f.denizens.Load())
	}
	stored, _ := store.Load(ctx)
	if stored.APIToken != ta {
		t.Errorf("stored api token %q", stored.APIToken)
	}
}

func TestInvalidateAPIToken(t *testing.T) {
	f := newFake(t)
	f.apiTokens = true
	store := NewMemoryTokenStore(seedToken())
	ctx := context.Background()
	a := NewAuthenticator(AuthenticatorConfig{Config: f.cfg(), Store: store})
	first, err := a.APIToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Stale token: no-op.
	if err := a.InvalidateAPIToken(ctx, "something-else"); err != nil {
		t.Fatal(err)
	}
	if got, _ := a.APIToken(ctx); got != first || f.denizens.Load() != 1 {
		t.Errorf("stale invalidate changed state: %q, denizens=%d", got, f.denizens.Load())
	}
	// Exact token: cleared, persisted, and re-exchanged on next use.
	if err := a.InvalidateAPIToken(ctx, first); err != nil {
		t.Fatal(err)
	}
	if s, _ := store.Load(ctx); s.APIToken != "" {
		t.Error("store still has the API token")
	}
	second, err := a.APIToken(ctx)
	if err != nil || second == first {
		t.Fatalf("second = %q (%v), first = %q", second, err, first)
	}
	// Invalidating the old token again must not drop the newer one.
	if err := a.InvalidateAPIToken(ctx, first); err != nil {
		t.Fatal(err)
	}
	if got, _ := a.APIToken(ctx); got != second {
		t.Errorf("newer token lost: %q", got)
	}
}

func TestMemoryStoreCAS(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryTokenStore(nil)
	if got, err := s.Load(ctx); got != nil || err != nil {
		t.Fatalf("Load = %v, %v", got, err)
	}
	a := &Token{RefreshToken: "a"}
	if err := s.CompareAndSwap(ctx, nil, a); err != nil {
		t.Fatal(err)
	}
	if err := s.CompareAndSwap(ctx, nil, &Token{RefreshToken: "b"}); !errors.Is(err, ErrTokenConflict) {
		t.Errorf("err = %v", err)
	}
	if err := s.CompareAndSwap(ctx, &Token{RefreshToken: "x"}, a); !errors.Is(err, ErrTokenConflict) {
		t.Errorf("err = %v", err)
	}
	if err := s.CompareAndSwap(ctx, &Token{RefreshToken: "a", APIToken: "diff"}, a); !errors.Is(err, ErrTokenConflict) {
		t.Errorf("api token must be compared: %v", err)
	}
	if err := s.CompareAndSwap(ctx, a, &Token{RefreshToken: "c"}); err != nil {
		t.Fatal(err)
	}
}

func TestFileTokenStore(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sub", "token.json")
	s := NewFileTokenStore(path)
	if got, err := s.Load(ctx); got != nil || err != nil {
		t.Fatalf("missing file: %v, %v", got, err)
	}
	want := &Token{
		AccessToken: "a", RefreshToken: "r", IDToken: "i", APIToken: "p", Region: "eu",
		Expiry: time.Now().Add(time.Hour).UTC().Truncate(time.Second), APITokenIssuedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := s.CompareAndSwap(ctx, nil, want); err != nil {
		t.Fatal(err)
	}
	if err := s.CompareAndSwap(ctx, nil, want); !errors.Is(err, ErrTokenConflict) {
		t.Errorf("err = %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", fi.Mode().Perm())
	}
	got, err := s.Load(ctx)
	if err != nil || *got != *want {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	raw, _ := os.ReadFile(path)
	for _, k := range []string{`"access_token"`, `"refresh_token"`, `"id_token"`, `"expiry"`, `"api_token"`, `"api_token_issued_at"`, `"region"`} {
		if !bytes.Contains(raw, []byte(k)) {
			t.Errorf("file lacks %s: %s", k, raw)
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("leftover temp files: %v", entries)
	}
	next := &Token{RefreshToken: "r2"}
	if err := s.CompareAndSwap(ctx, got, next); err != nil {
		t.Fatal(err)
	}
}

func TestTokenLogValueHidesSecrets(t *testing.T) {
	tok := &Token{
		AccessToken: "SECRET_ACCESS", RefreshToken: "SECRET_REFRESH", IDToken: "SECRET_ID", APIToken: "SECRET_API",
		Expiry: time.Now(), Region: "na",
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "token", tok)
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "token", tok)
	out := buf.String() + fmt.Sprint(tok) + fmt.Sprintf("%v %+v %s", tok, tok, tok)
	if strings.Contains(out, "SECRET") {
		t.Errorf("secret leaked: %s", out)
	}
	if !strings.Contains(out, "region") {
		t.Errorf("expected metadata in %s", out)
	}
	var nilTok *Token
	_ = nilTok.LogValue()
}
