package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Public OAuth client parameters of the resident mobile app (spec 3.1).
const (
	publicClientID    = "0e3aeeb7cec2782b9fb21352a4349a44405ed5d7674072416b6481d51abfd6b6"
	publicRedirectURI = "com.butterflymx.oauth://oauth"
	publicScope       = "openid profile"

	// DefaultUserAgent is the app user agent used for API calls (spec 3.8).
	DefaultUserAgent = "butterflymx/1001.125.2 (com.butterflymx.butterflymx; build:1266; iOS 27.2.0) Alamofire/5.10.2"
	// DefaultWebUserAgent is the mobile Safari user agent used for the accounts web flow.
	DefaultWebUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 Mobile/15E148 Safari/604.1"
)

// Config describes one ButterflyMX environment and OAuth client.
type Config struct {
	AccountsURL string `json:"accounts_url"`
	APIURL      string `json:"api_url"`
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	Scope       string `json:"scope"`

	// UserAgent is sent on API calls. Default: [DefaultUserAgent].
	UserAgent string `json:"user_agent,omitzero"`
	// WebUserAgent is sent during the accounts web flow. Default: [DefaultWebUserAgent].
	WebUserAgent string `json:"web_user_agent,omitzero"`
	// Device is sent in the denizen login. Default: iOS 1001.125.2, en-US, no push tokens.
	Device DeviceInfo `json:"device,omitzero"`

	// HTTPClient is an optional base client (transport, timeout, proxy). The
	// interactive login flow never uses its cookie jar or redirect policy.
	HTTPClient *http.Client `json:"-"`

	// Now is an optional clock for everything in this package that reads
	// wall-clock time: [MFAChallenge.CreatedAt] and the [MFAChallengeTTL]
	// checks, [Token.Expiry] and [Token.APITokenIssuedAt] computed by
	// [ExchangeCode], [Refresh] and the API-token exchange. Nil means
	// [time.Now]. It is for tests and simulations; it is never serialized.
	//
	// A challenge created under a Config with Now remembers that clock only
	// in memory: a challenge restored with [MFAChallenge.UnmarshalBinary] uses
	// the Now of the Config passed to [CompleteLogin], [SwitchMFAMethod] or
	// [ResendMFACode] (or [time.Now]). [AuthenticatorConfig.Now] overrides
	// this field for an [Authenticator].
	Now func() time.Time `json:"-"`
}

// clock returns c.Now, or [time.Now] when it is nil.
func (c Config) clock() func() time.Time {
	if c.Now != nil {
		return c.Now
	}
	return time.Now
}

// DeviceInfo identifies the (virtual) device in the denizen login.
type DeviceInfo struct {
	Platform  string   `json:"platform"`
	Version   string   `json:"version"`
	Locales   []string `json:"locales"`
	Token     string   `json:"token,omitzero"`
	VoIPToken string   `json:"voip_token,omitzero"`
}

// ConfigFor returns a Config for any deployment: a local fake, a proxy or a
// future region. It uses the public OAuth client id, redirect URI, scope, user
// agents and device defaults of the resident app, with accountsURL and apiURL
// as the base URLs (trailing slashes are trimmed; nothing else is validated).
// The presets [Production], [ProductionEU], [Staging] and [Sandbox] are
// exactly ConfigFor of their URLs, and the root package's
// Environment.AuthConfig builds on this function.
func ConfigFor(accountsURL, apiURL string) Config {
	c := Config{
		AccountsURL: strings.TrimRight(accountsURL, "/"),
		APIURL:      strings.TrimRight(apiURL, "/"),
	}.withDefaults()
	c.HTTPClient, c.Now = nil, nil
	return c
}

// Environment presets (hosts from spec section 2).
var (
	Production = ConfigFor("https://accounts.butterflymx.com", "https://api.butterflymx.com")
	// ProductionEU shares the accounts host with Production.
	ProductionEU = ConfigFor("https://accounts.butterflymx.com", "https://eu.api.butterflymx.com")
	Staging      = ConfigFor("https://accounts.na.staging.butterflymx.com", "https://api.na.staging.butterflymx.com")
	Sandbox      = ConfigFor("https://accounts.na.sandbox.butterflymx.com", "https://api.na.sandbox.butterflymx.com")
)

// Sentinel errors.
var (
	ErrInvalidCredentials   = errors.New("auth: invalid email or password")
	ErrInvalidMFACode       = errors.New("auth: invalid two-factor code")
	ErrMFAExpired           = errors.New("auth: two-factor challenge expired")
	ErrMFAMethodUnsupported = errors.New("auth: two-factor method not supported")
	ErrReauthRequired       = errors.New("auth: re-authentication required")
	ErrLoginFlowChanged     = errors.New("auth: login flow changed unexpectedly")
	ErrStateMismatch        = errors.New("auth: OAuth state mismatch")
	ErrTokenConflict        = errors.New("auth: token store conflict")
)

// Error is returned for unexpected HTTP responses from ButterflyMX.
type Error struct {
	Op          string // e.g. "token", "denizen login"
	Status      int
	Code        string // OAuth "error" field, when present
	Description string
	Body        string // truncated
}

func (e *Error) Error() string {
	s := fmt.Sprintf("auth: %s: HTTP %d", e.Op, e.Status)
	if e.Code != "" {
		s += " " + e.Code
	}
	if e.Description != "" {
		s += ": " + e.Description
	} else if e.Code == "" && e.Body != "" {
		s += ": " + e.Body
	}
	return s
}

// withDefaults returns a copy of c with empty fields defaulted.
func (c Config) withDefaults() Config {
	c.AccountsURL = strings.TrimRight(c.AccountsURL, "/")
	c.APIURL = strings.TrimRight(c.APIURL, "/")
	if c.ClientID == "" {
		c.ClientID = publicClientID
	}
	if c.RedirectURI == "" {
		c.RedirectURI = publicRedirectURI
	}
	if c.Scope == "" {
		c.Scope = publicScope
	}
	if c.UserAgent == "" {
		c.UserAgent = DefaultUserAgent
	}
	if c.WebUserAgent == "" {
		c.WebUserAgent = DefaultWebUserAgent
	}
	if c.Device.Platform == "" {
		c.Device.Platform = "ios"
	}
	if c.Device.Version == "" {
		c.Device.Version = "1001.125.2"
	}
	if len(c.Device.Locales) == 0 {
		c.Device.Locales = []string{"en-US"}
	}
	if c.HTTPClient == nil {
		c.HTTPClient = http.DefaultClient
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// forRegion returns the config to use for API calls in region. The EU region
// has its own API host; it is selected only when the config points at the
// production NA API.
func (c Config) forRegion(region string) Config {
	if region == "eu" && c.APIURL == strings.TrimRight(Production.APIURL, "/") {
		c.APIURL = ProductionEU.APIURL
	}
	return c
}

func (c Config) validate() error {
	for name, v := range map[string]string{"AccountsURL": c.AccountsURL, "APIURL": c.APIURL} {
		u, err := url.Parse(v)
		if err != nil || u.Host == "" {
			return fmt.Errorf("auth: invalid Config.%s %q", name, v)
		}
	}
	return nil
}
