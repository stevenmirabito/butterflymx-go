package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// AuthenticatorConfig configures an [Authenticator].
type AuthenticatorConfig struct {
	Config Config
	Store  TokenStore
	// Relogin is optional. It is called when the refresh token is rejected (or
	// no token is stored) and must return a fresh token, for example by
	// prompting the resident. When nil, [ErrReauthRequired] is returned.
	Relogin func(ctx context.Context) (*Token, error)
	// Now is an optional clock, for tests. When nil it defaults to
	// Config.Now (and then [time.Now]); when both are set, this field wins and
	// is also used for the token times computed by the exchanges the
	// Authenticator performs, so all time sources of one login are consistent.
	Now    func() time.Time
	Logger *slog.Logger // optional
}

// Authenticator keeps an OAuth token and API token fresh and persisted. It is
// safe for concurrent use and satisfies the root package's TokenProvider.
type Authenticator struct {
	cfg     Config
	store   TokenStore
	relogin func(ctx context.Context) (*Token, error)
	now     func() time.Time
	log     *slog.Logger

	mu       sync.Mutex
	loaded   bool
	cur      *Token
	inflight *flight
}

type flight struct {
	done chan struct{}
	err  error
}

// NewAuthenticator returns an Authenticator. Store defaults to an empty MemoryTokenStore.
func NewAuthenticator(c AuthenticatorConfig) *Authenticator {
	cfg := c.Config.withDefaults()
	if c.Now != nil {
		cfg.Now = c.Now
	}
	a := &Authenticator{
		cfg: cfg, store: c.Store, relogin: c.Relogin, now: cfg.Now, log: c.Logger,
	}
	if a.store == nil {
		a.store = NewMemoryTokenStore(nil)
	}
	if a.log == nil {
		a.log = slog.New(slog.DiscardHandler)
	}
	return a
}

// snapshot returns a copy of the cached token, loading from the store on first use.
func (a *Authenticator) snapshot(ctx context.Context) (*Token, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.loaded {
		t, err := a.store.Load(ctx)
		if err != nil {
			return nil, err
		}
		a.cur, a.loaded = t, true
	}
	return a.cur.clone(), nil
}

func (a *Authenticator) setCur(t *Token) {
	a.mu.Lock()
	a.cur, a.loaded = t.clone(), true
	a.mu.Unlock()
}

// satisfied reports whether tok already provides what the caller needs.
func (a *Authenticator) satisfied(tok *Token, needAPI bool) bool {
	if tok == nil {
		return false
	}
	if needAPI {
		return tok.APIToken != ""
	}
	return tok.oauthValid(a.now())
}

// Token returns the current token, refreshing the OAuth token if it has less
// than 60 seconds left.
func (a *Authenticator) Token(ctx context.Context) (*Token, error) {
	return a.get(ctx, false)
}

// APIToken returns the API (denizen) token, performing a refresh and/or denizen
// login if needed. Concurrent callers share a single exchange.
func (a *Authenticator) APIToken(ctx context.Context) (string, error) {
	t, err := a.get(ctx, true)
	if err != nil {
		return "", err
	}
	return t.APIToken, nil
}

func (a *Authenticator) get(ctx context.Context, needAPI bool) (*Token, error) {
	for range 8 {
		tok, err := a.snapshot(ctx)
		if err != nil {
			return nil, err
		}
		if a.satisfied(tok, needAPI) {
			return tok, nil
		}
		if err := a.singleflight(ctx, needAPI); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("auth: could not obtain a usable token")
}

// singleflight runs ensure once for all concurrent callers.
func (a *Authenticator) singleflight(ctx context.Context, needAPI bool) error {
	a.mu.Lock()
	if f := a.inflight; f != nil {
		a.mu.Unlock()
		select {
		case <-f.done:
		case <-ctx.Done():
			return ctx.Err()
		}
		// The leader's own cancellation must not fail followers: retry.
		if f.err != nil && (errors.Is(f.err, context.Canceled) || errors.Is(f.err, context.DeadlineExceeded)) && ctx.Err() == nil {
			return nil
		}
		return f.err
	}
	f := &flight{done: make(chan struct{})}
	a.inflight = f
	a.mu.Unlock()

	f.err = a.ensure(ctx, needAPI)

	a.mu.Lock()
	a.inflight = nil
	a.mu.Unlock()
	close(f.done)
	return f.err
}

// reload re-reads the store into the cache.
func (a *Authenticator) reload(ctx context.Context) (*Token, error) {
	t, err := a.store.Load(ctx)
	if err != nil {
		return nil, err
	}
	a.setCur(t)
	return t, nil
}

func isStatus(err error, status int) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == status
}

// ensure does the actual refresh/exchange work. Only one runs at a time.
func (a *Authenticator) ensure(ctx context.Context, needAPI bool) error {
	tok, err := a.snapshot(ctx)
	if err != nil {
		return err
	}
	forcedRefresh, usedForced := false, false
	for attempt := 0; attempt < 4; attempt++ {
		if a.satisfied(tok, needAPI) {
			a.setCur(tok)
			return nil
		}
		prev := tok

		// 1. Make sure the OAuth token is usable.
		if tok == nil || !tok.oauthValid(a.now()) || forcedRefresh {
			next, err := a.renew(ctx, tok)
			if err != nil {
				return err
			}
			forcedRefresh = false
			if err := a.casStore(ctx, prev, next); err != nil {
				if errors.Is(err, ErrTokenConflict) {
					re, lerr := a.reload(ctx)
					if lerr != nil {
						return lerr
					}
					a.log.Debug("token store conflict, reloaded", "token", re)
					tok = re
					continue
				}
				return err
			}
			a.setCur(next)
			tok, prev = next, next
		}
		if !needAPI {
			continue
		}

		// 2. Denizen login.
		api, err := DenizenLogin(ctx, a.cfg.forRegion(tok.Region), tok.AccessToken)
		if err != nil {
			if isStatus(err, http.StatusUnauthorized) && !usedForced {
				a.log.Debug("denizen login rejected, forcing OAuth refresh")
				forcedRefresh, usedForced = true, true
				continue
			}
			return err
		}
		next := tok.clone()
		next.APIToken = api
		next.APITokenIssuedAt = a.now()
		if err := a.casStore(ctx, prev, next); err != nil {
			if errors.Is(err, ErrTokenConflict) {
				re, lerr := a.reload(ctx)
				if lerr != nil {
					return lerr
				}
				tok = re
				continue
			}
			return err
		}
		a.setCur(next)
		tok = next
	}
	return errors.New("auth: token store kept changing underneath us")
}

func (a *Authenticator) casStore(ctx context.Context, prev, next *Token) error {
	return a.store.CompareAndSwap(ctx, prev, next)
}

// renew refreshes tok's OAuth token, falling back to Relogin.
func (a *Authenticator) renew(ctx context.Context, tok *Token) (*Token, error) {
	if tok != nil && tok.RefreshToken != "" {
		next, err := Refresh(ctx, a.cfg, tok.RefreshToken)
		if err == nil {
			// Carry over fields the refresh response does not know about.
			next.APIToken, next.APITokenIssuedAt, next.Region = tok.APIToken, tok.APITokenIssuedAt, tok.Region
			if next.IDToken == "" {
				next.IDToken = tok.IDToken
			}
			if next.Expiry.IsZero() {
				next.Expiry = a.now().Add(time.Hour)
			}
			return next, nil
		}
		if !errors.Is(err, ErrReauthRequired) {
			return nil, err
		}
	}
	if a.relogin == nil {
		return nil, ErrReauthRequired
	}
	a.log.Info("refresh failed, calling Relogin")
	next, err := a.relogin(ctx)
	if err != nil {
		return nil, err
	}
	if next == nil {
		return nil, ErrReauthRequired
	}
	return next.clone(), nil
}

// InvalidateAPIToken discards the cached API token if it is still token (the
// exact token a request just failed with). A newer token is left alone.
func (a *Authenticator) InvalidateAPIToken(ctx context.Context, token string) error {
	for range 3 {
		cur, err := a.snapshot(ctx)
		if err != nil {
			return err
		}
		if cur == nil || token == "" || cur.APIToken != token {
			return nil
		}
		next := cur.clone()
		next.APIToken = ""
		next.APITokenIssuedAt = time.Time{}
		err = a.casStore(ctx, cur, next)
		if err == nil {
			// Only replace the cache if it has not moved on in the meantime.
			a.mu.Lock()
			if a.cur != nil && a.cur.APIToken == token {
				a.cur = next.clone()
			}
			a.mu.Unlock()
			return nil
		}
		if !errors.Is(err, ErrTokenConflict) {
			return err
		}
		if _, err := a.reload(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Logout signs out: if the current token has an API token it is invalidated
// on the server (the package-level [Logout]), then the stored token is deleted
// (when the store implements [TokenDeleter]) and the in-memory cache is
// dropped. If the server-side logout fails the local token is still deleted
// and the server error is returned, joined with any delete error. With no
// token it does nothing and returns nil.
//
// A store that is not a [TokenDeleter] cannot be cleared by the
// Authenticator: the caller must discard the stored token itself, and the
// Authenticator keeps using that store's contents on its next call.
func (a *Authenticator) Logout(ctx context.Context) error {
	tok, err := a.snapshot(ctx)
	if err != nil {
		return err
	}
	if tok == nil {
		return nil
	}
	var serverErr error
	if tok.APIToken != "" {
		serverErr = Logout(ctx, a.cfg.forRegion(tok.Region), tok.APIToken)
	}
	var delErr error
	if d, ok := a.store.(TokenDeleter); ok {
		delErr = d.Delete(ctx)
	}
	a.mu.Lock()
	a.cur, a.loaded = nil, false
	a.mu.Unlock()
	return errors.Join(serverErr, delErr)
}
