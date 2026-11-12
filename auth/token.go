package auth

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Token holds the OAuth tokens and the derived API (denizen) token.
type Token struct {
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token"`
	IDToken          string    `json:"id_token,omitzero"`
	Expiry           time.Time `json:"expiry,omitzero"`
	APIToken         string    `json:"api_token,omitzero"`
	APITokenIssuedAt time.Time `json:"api_token_issued_at,omitzero"`
	Region           string    `json:"region,omitzero"`
}

// LogValue implements [slog.LogValuer] without revealing any secret.
func (t *Token) LogValue() slog.Value {
	if t == nil {
		return slog.StringValue("<nil>")
	}
	return slog.GroupValue(
		slog.Bool("has_access_token", t.AccessToken != ""),
		slog.Bool("has_refresh_token", t.RefreshToken != ""),
		slog.Bool("has_api_token", t.APIToken != ""),
		slog.Time("expiry", t.Expiry),
		slog.String("region", t.Region),
	)
}

// String redacts all secrets.
func (t *Token) String() string {
	if t == nil {
		return "<nil>"
	}
	return fmt.Sprintf("auth.Token{expiry:%s api_token:%t refresh_token:%t region:%q}",
		t.Expiry.Format(time.RFC3339), t.APIToken != "", t.RefreshToken != "", t.Region)
}

func (t *Token) clone() *Token {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}

// oauthValid reports whether the OAuth access token has more than skew left.
func (t *Token) oauthValid(now time.Time) bool {
	return t != nil && t.AccessToken != "" && t.Expiry.Sub(now) > refreshSkew
}

const refreshSkew = 60 * time.Second

// sameIdentity is the CAS comparison: RefreshToken and APIToken.
func sameIdentity(a, b *Token) bool {
	return a.RefreshToken == b.RefreshToken && a.APIToken == b.APIToken
}

// TokenStore persists a Token. Implementations must be safe for concurrent use.
type TokenStore interface {
	// Load returns the stored token, or (nil, nil) when the store is empty.
	Load(ctx context.Context) (*Token, error)
	// CompareAndSwap stores next only if the stored token still equals prev
	// (same RefreshToken and APIToken). prev == nil means "only if empty".
	// Otherwise it returns [ErrTokenConflict].
	CompareAndSwap(ctx context.Context, prev, next *Token) error
}

// TokenDeleter is an optional interface of a [TokenStore] that can remove the
// stored token. [MemoryTokenStore] and [FileTokenStore] implement it;
// [Authenticator.Logout] uses it when available.
type TokenDeleter interface {
	// Delete removes the stored token. Deleting an empty store is not an error.
	Delete(ctx context.Context) error
}

var (
	_ TokenDeleter = (*MemoryTokenStore)(nil)
	_ TokenDeleter = (*FileTokenStore)(nil)
)

// MemoryTokenStore is an in-memory [TokenStore].
type MemoryTokenStore struct {
	mu  sync.Mutex
	tok *Token
}

// NewMemoryTokenStore returns a store optionally seeded with tok.
func NewMemoryTokenStore(tok *Token) *MemoryTokenStore {
	return &MemoryTokenStore{tok: tok.clone()}
}

func (s *MemoryTokenStore) Load(ctx context.Context) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tok.clone(), nil
}

func (s *MemoryTokenStore) CompareAndSwap(ctx context.Context, prev, next *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := checkCAS(s.tok, prev); err != nil {
		return err
	}
	s.tok = next.clone()
	return nil
}

// Delete clears the store.
func (s *MemoryTokenStore) Delete(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tok = nil
	return nil
}

func checkCAS(stored, prev *Token) error {
	switch {
	case prev == nil && stored == nil:
		return nil
	case prev == nil || stored == nil:
		return ErrTokenConflict
	case !sameIdentity(stored, prev):
		return ErrTokenConflict
	}
	return nil
}

// FileTokenStore stores the token as JSON in a file (mode 0600), written
// atomically. Compare-and-swap is atomic within one process only.
type FileTokenStore struct {
	path string
	mu   sync.Mutex
}

// NewFileTokenStore returns a store backed by path.
func NewFileTokenStore(path string) *FileTokenStore { return &FileTokenStore{path: path} }

func (s *FileTokenStore) read() (*Token, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	var t Token
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("auth: decode token file: %w", err)
	}
	return &t, nil
}

func (s *FileTokenStore) Load(ctx context.Context) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read()
}

// Delete removes the token file. A missing file is not an error.
func (s *FileTokenStore) Delete(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *FileTokenStore) CompareAndSwap(ctx context.Context, prev, next *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, err := s.read()
	if err != nil {
		return err
	}
	if err := checkCAS(stored, prev); err != nil {
		return err
	}
	data, err := json.Marshal(next, json.Deterministic(true))
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".token-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // no-op after successful rename
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
