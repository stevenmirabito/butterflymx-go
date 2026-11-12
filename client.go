package butterflymx

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// TokenProvider supplies the API (denizen) bearer token. *auth.Authenticator
// implements it.
type TokenProvider interface {
	// APIToken returns a valid token, refreshing it if needed.
	APIToken(ctx context.Context) (string, error)
	// InvalidateAPIToken discards token (which the server rejected) so the next
	// APIToken call returns a fresh one.
	InvalidateAPIToken(ctx context.Context, token string) error
}

// StaticAPIToken is a TokenProvider for a fixed token.
type StaticAPIToken string

// APIToken returns the fixed token.
func (t StaticAPIToken) APIToken(context.Context) (string, error) { return string(t), nil }

// InvalidateAPIToken is a no-op.
func (t StaticAPIToken) InvalidateAPIToken(context.Context, string) error { return nil }

// RetryPolicy controls automatic retries of idempotent requests (GET and
// DELETE, and GraphQL queries) on network errors, 5xx and 429. Delays use full
// jitter. Zero fields take the defaults.
type RetryPolicy struct {
	MaxAttempts int           // total attempts including the first; default 4
	BaseDelay   time.Duration // default 250ms
	MaxDelay    time.Duration // default 5s
}

// Options configures a Client.
type Options struct {
	// Environment is the deployment to talk to. The zero value means
	// [Production], unless Region is set.
	Environment Environment
	// Region selects a production environment by name, "na" or "eu" (see
	// [EnvironmentForRegion]); pass the signed-in account's [auth.Token].Region.
	// It is used only when Environment is the zero value. When both are set,
	// the explicit Environment wins, even if they disagree. A Region that is
	// not "na" or "eu" makes [New] fail with [ErrUnknownRegion], whether or
	// not it is used.
	Region string
	Auth   TokenProvider // required
	// HTTPClient is optional; the default has a 30s timeout.
	HTTPClient *http.Client
	Logger     *slog.Logger // optional; default discards
	UserAgent  string       // optional; default DefaultUserAgent
	Retry      RetryPolicy  // optional

	// SkipClientValidation turns off the client's own pre-flight checks so
	// that the server's answer can be observed.
	//
	// THIS IS FOR PROBING THE API AND FOR TESTS, NOT FOR PRODUCTION USE: with
	// it, malformed requests (an end before the start, a bad recipient, a
	// blank name) are sent to ButterflyMX, which may accept something this
	// library considers invalid, or may create passes and send messages.
	// A request the server rejects still returns the usual [*Error].
	//
	// It skips [CustomSchedule.Validate] and [RecurringSchedule.Validate] (a
	// nil or unknown Schedule type is still an error, since the request path
	// depends on it), [Recipient.Validate], the "name is required" and "at
	// least one access point" checks of [Client.CreateKeychain], the "at least
	// one recipient" check of [Client.AddVirtualKeys], and the name and end
	// time checks of [Client.UpdateDeliveryPass] and
	// [Client.ExtendDeliveryPass]. Names are then sent as given instead of
	// trimmed. Conversions needed to build a request, such as
	// [GlobalID.As] (which fails with [ErrIDType]), always run.
	SkipClientValidation bool
}

// Client is a ButterflyMX API client. It is safe for concurrent use.
type Client struct {
	cfg   Options
	env   Environment
	http  *http.Client
	log   *slog.Logger
	ua    string
	retry RetryPolicy

	sleep func(ctx context.Context, d time.Duration) error // replaced in tests
}

// New validates opts and returns a Client.
func New(opts Options) (*Client, error) {
	if opts.Auth == nil {
		return nil, errors.New("butterflymx: Options.Auth is required")
	}
	env := opts.Environment
	var regionEnv Environment
	if opts.Region != "" {
		e, err := EnvironmentForRegion(opts.Region)
		if err != nil {
			return nil, err
		}
		regionEnv = e
	}
	if env == (Environment{}) {
		env = Production
		if regionEnv != (Environment{}) {
			env = regionEnv
		}
	}
	if err := env.Validate(); err != nil {
		return nil, err
	}
	c := &Client{cfg: opts, env: env, http: opts.HTTPClient, log: opts.Logger, ua: opts.UserAgent, retry: opts.Retry, sleep: sleepCtx}
	if c.http == nil {
		c.http = &http.Client{Timeout: 30 * time.Second}
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if c.ua == "" {
		c.ua = DefaultUserAgent
	}
	if c.retry.MaxAttempts <= 0 {
		c.retry.MaxAttempts = 4
	}
	if c.retry.BaseDelay <= 0 {
		c.retry.BaseDelay = 250 * time.Millisecond
	}
	if c.retry.MaxDelay <= 0 {
		c.retry.MaxDelay = 5 * time.Second
	}
	return c, nil
}

// Environment returns the environment the client talks to.
func (c *Client) Environment() Environment { return c.env }
