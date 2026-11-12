package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileTokenStoreDelete(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sub", "token.json")
	s := NewFileTokenStore(path)

	// A missing file is not an error.
	if err := s.Delete(ctx); err != nil {
		t.Fatalf("Delete missing: %v", err)
	}
	if err := s.CompareAndSwap(ctx, nil, seedToken()); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("file still there: %v", err)
	}
	if tok, err := s.Load(ctx); tok != nil || err != nil {
		t.Errorf("Load after Delete = %v, %v", tok, err)
	}
	// The store is usable again.
	if err := s.CompareAndSwap(ctx, nil, seedToken()); err != nil {
		t.Errorf("CAS after Delete: %v", err)
	}
}

func TestMemoryTokenStoreDelete(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryTokenStore(seedToken())
	if err := s.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	if tok, err := s.Load(ctx); tok != nil || err != nil {
		t.Errorf("Load after Delete = %v, %v", tok, err)
	}
	if err := s.Delete(ctx); err != nil {
		t.Errorf("Delete empty: %v", err)
	}
	var _ TokenDeleter = s
	var _ TokenDeleter = NewFileTokenStore("x")
}

func apiSeed(api string) *Token {
	t := seedToken()
	t.APIToken, t.APITokenIssuedAt = api, time.Now()
	return t
}

func TestAuthenticatorLogout(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	store := NewMemoryTokenStore(apiSeed("tok")) // the fake accepts Bearer tok
	a := NewAuthenticator(AuthenticatorConfig{Config: f.cfg(), Store: store})
	if _, err := a.Token(ctx); err != nil { // warm the cache
		t.Fatal(err)
	}
	if err := a.Logout(ctx); err != nil {
		t.Fatal(err)
	}
	if tok, _ := store.Load(ctx); tok != nil {
		t.Errorf("store not emptied: %v", tok)
	}
	if f.logouts.Load() != 1 {
		t.Errorf("server logouts = %d", f.logouts.Load())
	}
	// The cache was dropped too: with no token and no Relogin we need reauth.
	if _, err := a.Token(ctx); !errors.Is(err, ErrReauthRequired) {
		t.Errorf("Token after Logout err = %v", err)
	}
}

func TestAuthenticatorLogoutServerFailure(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	store := NewMemoryTokenStore(apiSeed("rejected")) // the fake answers 401
	a := NewAuthenticator(AuthenticatorConfig{Config: f.cfg(), Store: store})
	err := a.Logout(ctx)
	if !isStatus(err, 401) {
		t.Fatalf("err = %v, want HTTP 401", err)
	}
	if tok, _ := store.Load(ctx); tok != nil {
		t.Errorf("store must still be cleared: %v", tok)
	}
}

func TestAuthenticatorLogoutNoToken(t *testing.T) {
	f := newFake(t)
	a := NewAuthenticator(AuthenticatorConfig{Config: f.cfg()})
	before := f.requests.Load()
	if err := a.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.requests.Load() != before {
		t.Error("no request expected")
	}
}

func TestAuthenticatorLogoutWithoutAPIToken(t *testing.T) {
	f := newFake(t)
	store := NewMemoryTokenStore(seedToken())
	a := NewAuthenticator(AuthenticatorConfig{Config: f.cfg(), Store: store})
	before := f.requests.Load()
	if err := a.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.requests.Load() != before {
		t.Error("no server logout expected without an API token")
	}
	if tok, _ := store.Load(context.Background()); tok != nil {
		t.Errorf("store not emptied: %v", tok)
	}
}

// plainStore is a TokenStore that is not a TokenDeleter.
type plainStore struct{ inner *MemoryTokenStore }

func (p plainStore) Load(ctx context.Context) (*Token, error) { return p.inner.Load(ctx) }
func (p plainStore) CompareAndSwap(ctx context.Context, prev, next *Token) error {
	return p.inner.CompareAndSwap(ctx, prev, next)
}

func TestAuthenticatorLogoutStoreWithoutDeleter(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	inner := NewMemoryTokenStore(apiSeed("tok"))
	a := NewAuthenticator(AuthenticatorConfig{Config: f.cfg(), Store: plainStore{inner}})
	if err := a.Logout(ctx); err != nil {
		t.Fatal(err)
	}
	if f.logouts.Load() != 1 {
		t.Errorf("server logouts = %d", f.logouts.Load())
	}
	// The caller must discard the token: the store still has it.
	if tok, _ := inner.Load(ctx); tok == nil {
		t.Error("store unexpectedly cleared")
	}
}

// failingDeleter fails Delete.
type failingDeleter struct{ plainStore }

var errDelete = errors.New("delete failed")

func (failingDeleter) Delete(context.Context) error { return errDelete }

func TestAuthenticatorLogoutJoinsErrors(t *testing.T) {
	f := newFake(t)
	st := failingDeleter{plainStore{NewMemoryTokenStore(apiSeed("rejected"))}}
	a := NewAuthenticator(AuthenticatorConfig{Config: f.cfg(), Store: st})
	err := a.Logout(context.Background())
	if !errors.Is(err, errDelete) || !isStatus(err, 401) {
		t.Errorf("err = %v, want both the server and the delete error", err)
	}
}
