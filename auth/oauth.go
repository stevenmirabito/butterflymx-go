package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxBody = 2 << 20

// randomString returns a 43-char base64url string (32 random bytes).
func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func constEq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "...(truncated)"
	}
	return s
}

// authorizeURL builds the authorize URL (spec 3.2 step 1).
func authorizeURL(cfg Config, challenge, state, nonce string) string {
	q := url.Values{
		"client_id":             {cfg.ClientID},
		"redirect_uri":          {cfg.RedirectURI},
		"response_type":         {"code"},
		"scope":                 {cfg.Scope},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"nonce":                 {nonce},
		"state":                 {state},
		"prompt":                {"login"},
	}
	return cfg.AccountsURL + "/oauth/authorize?" + q.Encode()
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// do sends req with the base client and returns status and body.
func do(cfg Config, req *http.Request) (int, []byte, error) {
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return resp.StatusCode, body, err
}

func postToken(ctx context.Context, cfg Config, op string, form url.Values) (*Token, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.AccountsURL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", cfg.UserAgent)
	status, body, err := do(cfg, req)
	if err != nil {
		return nil, 0, err
	}
	var tr tokenResponse
	jsonErr := json.Unmarshal(body, &tr)
	if status != http.StatusOK {
		return nil, status, &Error{Op: op, Status: status, Code: tr.Error, Description: tr.ErrorDesc, Body: truncate(string(body), 200)}
	}
	if jsonErr != nil || tr.AccessToken == "" {
		return nil, status, &Error{Op: op, Status: status, Description: "malformed token response"}
	}
	t := &Token{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		IDToken:      tr.IDToken,
	}
	if tr.ExpiresIn > 0 {
		t.Expiry = cfg.clock()().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return t, status, nil
}

// ExchangeCode exchanges an authorization code (with its PKCE verifier) for an
// OAuth token (spec 3.4). The returned Token has no API token yet.
func ExchangeCode(ctx context.Context, cfg Config, code, verifier string) (*Token, error) {
	cfg = cfg.withDefaults()
	t, _, err := postToken(ctx, cfg, "token exchange", url.Values{
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {cfg.RedirectURI},
		"client_id":     {cfg.ClientID},
		"grant_type":    {"authorization_code"},
	})
	return t, err
}

// Refresh redeems a refresh token (spec 3.5). If the response omits a new
// refresh token the old one is kept. invalid_grant yields [ErrReauthRequired].
func Refresh(ctx context.Context, cfg Config, refreshToken string) (*Token, error) {
	cfg = cfg.withDefaults()
	t, status, err := postToken(ctx, cfg, "token refresh", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {cfg.ClientID},
	})
	if err != nil {
		var ae *Error
		if errors.As(err, &ae) && (status == http.StatusBadRequest || status == http.StatusUnauthorized) && ae.Code == "invalid_grant" {
			return nil, fmt.Errorf("%w: refresh token rejected", ErrReauthRequired)
		}
		return nil, err
	}
	if t.RefreshToken == "" {
		t.RefreshToken = refreshToken
	}
	return t, nil
}

// Regions lists the account's regions using the OAuth access token (spec 2).
func Regions(ctx context.Context, cfg Config, accessToken string) ([]string, error) {
	cfg = cfg.withDefaults()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.AccountsURL+"/api/mobile/regions", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", cfg.UserAgent)
	status, body, err := do(cfg, req)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, &Error{Op: "regions", Status: status, Body: truncate(string(body), 200)}
	}
	var out struct {
		Regions []string `json:"regions"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &Error{Op: "regions", Status: status, Description: "malformed response"}
	}
	return out.Regions, nil
}

// DenizenLogin exchanges an OAuth access token for an API token (spec 3.6).
// A 401 is returned as an *[Error] with Status 401.
func DenizenLogin(ctx context.Context, cfg Config, accessToken string) (string, error) {
	cfg = cfg.withDefaults()
	payload, err := json.Marshal(struct {
		AccessToken string     `json:"access_token"`
		Device      DeviceInfo `json:"device"`
	}{accessToken, cfg.Device})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.APIURL+"/denizen/v1/login", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", cfg.UserAgent)
	status, body, err := do(cfg, req)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", &Error{Op: "denizen login", Status: status, Body: truncate(string(body), 200)}
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Token == "" {
		return "", &Error{Op: "denizen login", Status: status, Description: "malformed response"}
	}
	return out.Token, nil
}

// Logout invalidates an API token (spec 3.7).
func Logout(ctx context.Context, cfg Config, apiToken string) error {
	cfg = cfg.withDefaults()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, cfg.APIURL+"/denizen/v1/logout", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", cfg.UserAgent)
	status, body, err := do(cfg, req)
	if err != nil {
		return err
	}
	if status < 200 || status > 299 {
		return &Error{Op: "logout", Status: status, Body: truncate(string(body), 200)}
	}
	return nil
}

// completeFromCode runs code exchange, region discovery and denizen login.
func completeFromCode(ctx context.Context, cfg Config, code, verifier string) (*Token, error) {
	cfg = cfg.withDefaults()
	tok, err := ExchangeCode(ctx, cfg, code, verifier)
	if err != nil {
		return nil, err
	}
	return exchangeAPIToken(ctx, cfg, tok)
}

// exchangeAPIToken fills in Region and APIToken on tok (modified in place).
func exchangeAPIToken(ctx context.Context, cfg Config, tok *Token) (*Token, error) {
	regions, err := Regions(ctx, cfg, tok.AccessToken)
	if err != nil {
		return nil, err
	}
	tok.Region = "na"
	if len(regions) > 0 && regions[0] != "" {
		tok.Region = regions[0]
	}
	api, err := DenizenLogin(ctx, cfg.forRegion(tok.Region), tok.AccessToken)
	if err != nil {
		return nil, err
	}
	tok.APIToken = api
	tok.APITokenIssuedAt = cfg.clock()()
	return tok, nil
}

// AuthCodeFlow is the browser-assisted fallback: the caller opens a URL in a
// browser, signs in, and pastes back the final com.butterflymx.oauth:// URL.
type AuthCodeFlow struct{ cfg Config }

// AuthCodeStart is the serializable state between Start and Finish.
type AuthCodeStart struct {
	URL      string `json:"url"`
	State    string `json:"state"`
	Verifier string `json:"verifier"`
}

// NewAuthCodeFlow returns a flow for cfg.
func NewAuthCodeFlow(cfg Config) *AuthCodeFlow { return &AuthCodeFlow{cfg: cfg.withDefaults()} }

// Start generates PKCE values and the authorize URL.
func (f *AuthCodeFlow) Start() (AuthCodeStart, error) {
	verifier, err := randomString()
	if err != nil {
		return AuthCodeStart{}, err
	}
	state, err := randomString()
	if err != nil {
		return AuthCodeStart{}, err
	}
	nonce, err := randomString()
	if err != nil {
		return AuthCodeStart{}, err
	}
	return AuthCodeStart{
		URL:      authorizeURL(f.cfg, pkceChallenge(verifier), state, nonce),
		State:    state,
		Verifier: verifier,
	}, nil
}

// Finish validates the redirected URL (state), exchanges the code, discovers
// the region and performs the denizen login.
func (f *AuthCodeFlow) Finish(ctx context.Context, s AuthCodeStart, redirectedURL string) (*Token, error) {
	code, err := codeFromRedirect(f.cfg, strings.TrimSpace(redirectedURL), s.State)
	if err != nil {
		return nil, err
	}
	return completeFromCode(ctx, f.cfg, code, s.Verifier)
}

// codeFromRedirect extracts and validates the code from the final redirect.
func codeFromRedirect(cfg Config, loc, state string) (string, error) {
	u, err := url.Parse(loc)
	if err != nil || !strings.HasPrefix(loc, cfg.RedirectURI) {
		return "", fmt.Errorf("%w: not a redirect to %s", ErrLoginFlowChanged, cfg.RedirectURI)
	}
	q := u.Query()
	if e := q.Get("error"); e != "" {
		return "", fmt.Errorf("auth: authorization failed: %s", e)
	}
	if !constEq(q.Get("state"), state) || state == "" {
		return "", ErrStateMismatch
	}
	code := q.Get("code")
	if code == "" {
		return "", fmt.Errorf("%w: redirect has no code", ErrLoginFlowChanged)
	}
	return code, nil
}
