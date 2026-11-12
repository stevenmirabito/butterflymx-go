# butterflymx-go

An unofficial Go client for the ButterflyMX resident API, built to grant and
revoke guest access (PIN and QR virtual keys) to ButterflyMX buildings on
behalf of a resident.

> [!WARNING]
> **Unofficial and unsupported.** This project is not affiliated with,
> endorsed by, or supported by ButterflyMX. It uses the same private API as
> the official mobile apps, which can change or stop working at any time.
> Use it only with your own account and only for doors you are authorized to
> open. You are responsible for complying with ButterflyMX's Terms of Service
> and your building's policies.

## What it is

A complete client for the HTTP API behind the ButterflyMX resident app:
sign-in (including 2FA by authenticator app, SMS or email), tenancies, doors, unlocking,
guest passes and delivery passes, history, and escape hatches for raw
GraphQL and REST calls. It also ships a stateful fake server for tests.

## Install

```sh
go get github.com/stevenmirabito/butterflymx-go
```

Requires Go 1.27 or later.

## Quickstart: logging in with 2FA

Login is a two-step flow that can be resumed. `auth.StartLogin` submits the
email and password. If the account has 2FA, it returns a serializable
`*auth.MFAChallenge` instead of a token. `auth.CompleteLogin` takes the
challenge and the 6-digit code. A web backend usually spreads these across
separate HTTP requests, possibly handled by different replicas, so you need to
be able to park the challenge in between.

```go
func start(ctx context.Context, email, password string) (blob []byte, hint string, tok *auth.Token, err error) {
	res, err := auth.StartLogin(ctx, auth.Production, email, password)
	if err != nil {
		return nil, "", nil, err // auth.ErrInvalidCredentials, auth.ErrLoginFlowChanged, ...
	}
	if res.Token != nil { // account without 2FA
		return nil, "", res.Token, nil
	}
	ch := res.Challenge
	switch ch.Method { // what to tell the user
	case auth.MFASMS:
		hint = "Enter the code we sent to " + ch.Destination // a masked number such as ******0100
	case auth.MFAEmail:
		hint = "Enter the code we emailed you" // the page shows no address, so Destination is empty
	default:
		hint = "Enter the code from your authenticator app"
	}
	blob, err = ch.MarshalBinary()
	return blob, hint, nil, err // store blob (encrypted, short TTL), ask the user for the code
}

func finish(ctx context.Context, blob []byte, code string) (*auth.Token, error) {
	var ch auth.MFAChallenge
	if err := ch.UnmarshalBinary(blob); err != nil {
		return nil, err
	}
	tok, err := auth.CompleteLogin(ctx, auth.Production, &ch, code)
	if errors.Is(err, auth.ErrInvalidMFACode) {
		// ch was updated in place: re-marshal it and let the user retry.
	}
	return tok, err // auth.ErrMFAExpired after auth.MFAChallengeTTL (10 minutes)
}
```

**Choosing and changing the method.** The server picks the first method: the
one used by the account's **last successful login** (authenticator app, SMS
or email). For SMS and email, the server sends the code, so the user will
have already received it when `StartLogin` returns. `MFAChallenge.Method`
and `Destination` tell you what to show.

```go
// Ask for a method up front instead of the server's default.
res, err := auth.StartLogin(ctx, auth.Production, email, password, auth.WithMFAMethod(auth.MFASMS))

// "Verify another way": switch a pending challenge. For sms and email this
// makes the server send a code. ch is updated in place: marshal it again.
err = auth.SwitchMFAMethod(ctx, auth.Production, &ch, auth.MFAEmail)

// "Resend code" (sms and email only; check ch.CanResend()).
err = auth.ResendMFACode(ctx, auth.Production, &ch)
if errors.Is(err, auth.ErrMFAResendUnsupported) { // authenticator app
}
```

`auth.ParseMFAMethod` turns user input such as "text" or "app" into an
`auth.MFAMethod`. The serialized challenge contains the login session's cookies,
the page's CSRF tokens and the PKCE verifier, so treat it as a secret: encrypt
it at rest and give it a short TTL (the library rejects challenges older than
`auth.MFAChallengeTTL` anyway). Delete it once the login succeeds.

The examples sign in to `auth.Production`. For another deployment (a proxy, a
local fake, or a region of your own) build the `auth.Config` from a
`butterflymx.Environment` so that the login and the client cannot disagree:
`butterflymx.LocalEnvironment(baseURL)` for a single host, then
`env.AuthConfig()`. `auth.ConfigFor(accountsURL, apiURL)` does the same
without the root package. `Config.Now` injects a clock for everything in the
login that reads the time (challenge ages, `MFAChallengeTTL` and the expiry
times in the token), which is how you test expiry without sleeping.

Persist the resulting `*auth.Token` in an `auth.TokenStore`. Refresh tokens
**rotate**: each refresh invalidates the previous one. If two replicas refresh
at the same time, the loser would otherwise overwrite the winner's token with a
dead one. `TokenStore.CompareAndSwap` prevents that: it stores the new token
only if the stored one is still the one you started from, and otherwise
returns `auth.ErrTokenConflict`, which the `Authenticator` resolves by
reloading. In a multi-replica deployment, implement `TokenStore` on a database
row with a conditional update. `auth.NewFileTokenStore` and
`auth.NewMemoryTokenStore` are provided for single-process use.

If the browser flow is easier for your users, `auth.NewAuthCodeFlow` offers a
fallback: open `Start().URL`, sign in, and paste the final redirect URL into
`Finish`.

## Quickstart: a guest pass

```go
a := auth.NewAuthenticator(auth.AuthenticatorConfig{
	Config: auth.Production,
	Store:  store, // your auth.TokenStore, seeded with the token from login
})
c, err := butterflymx.New(butterflymx.Options{
	Region: tok.Region, // "na" or "eu", from the login's *auth.Token
	Auth:   a,
})
if err != nil {
	return err
}

tenants, err := c.Tenants(ctx)
if err != nil {
	return err
}
tenant := tenants[0]
if !tenant.CanCreateGuestPasses() {
	return errors.New("guest passes are not available for this tenancy")
}

doors, err := c.AccessPoints(ctx, tenant.ID)
if err != nil {
	return err
}
var ids []butterflymx.GlobalID
for _, d := range doors {
	if d.SupportsVirtualKeys() {
		ids = append(ids, d.ID)
	}
}

now := time.Now()
kc, err := c.CreateKeychain(ctx, butterflymx.CreateKeychainParams{
	TenantID:       tenant.ID,
	AccessPointIDs: ids[:1],
	Name:           "Dog walker",
	Schedule:       butterflymx.CustomSchedule{StartsAt: now, EndsAt: now.Add(4 * time.Hour)},
	Recipients: []butterflymx.Recipient{
		butterflymx.EmailRecipient("Sam", "sam@example.com"),
		butterflymx.SMSRecipient("Alex", "(555) 555-0100"),
	},
})
if err != nil {
	return err
}
for _, k := range kc.VirtualKeys {
	fmt.Println(k.Name, k.PIN.Reveal(), k.QRCodeURL, k.InstructionsURL)
}

// Later: revoke the pass and all of its keys.
err = c.DeleteKeychain(ctx, kc.ID)
```

ButterflyMX itself emails or texts each recipient their key (the channel is
chosen from `DeliverTo`; delivery cannot be suppressed). `PIN` is redacted
when printed or logged, so call `Reveal` when you really need the digits.

**Recurring passes** use building-local wall-clock times, not instants. Load
the zone from the building:

```go
loc, err := tenant.Building.Location() // Building.TimeZone, e.g. "America/Los_Angeles"
if err != nil {
	return err
}
sched := butterflymx.RecurringSchedule{
	Weekdays:  []butterflymx.Weekday{butterflymx.Tuesday, butterflymx.Friday},
	From:      butterflymx.TimeOfDay{Hour: 9},
	To:        butterflymx.TimeOfDay{Hour: 17},
	StartDate: butterflymx.DateOf(now.In(loc)),
	EndDate:   butterflymx.DateOf(now.In(loc)).AddDays(90), // inclusive
}
```

Pass `sched` as `Schedule` in `CreateKeychainParams`. The server converts to
absolute instants using the building's zone.

**Delivery passes** are one-time keys with no recipients:

```go
dp, err := c.CreateDeliveryPass(ctx, butterflymx.DeliveryPassParams{TenantID: tenant.ID, Name: "Parcels"})
// ...
dp, err = c.ExtendDeliveryPass(ctx, dp.ID, 24*time.Hour)
```

A delivery pass always covers every door that supports virtual keys; the
server ignores any door list, so there is no option to choose doors.

**Guest passes are immutable.** The API has no endpoint to edit one. To change
a pass, create a new one with `CreateKeychain` and delete the old one with
`DeleteKeychain`.

## Regions and signing out

An account lives in one region, and `auth.Token.Region` records it after login
(`"na"` or `"eu"`). The two regions share the accounts host but have different
API hosts. Feed the region to the client so that it talks to the right one:

```go
c, err := butterflymx.New(butterflymx.Options{Region: tok.Region, Auth: a})
// or, to inspect or reuse the environment:
env, err := butterflymx.EnvironmentForRegion(tok.Region) // butterflymx.Production or ProductionEU
```

`Options.Region` is used only when `Options.Environment` is left empty (an
explicit `Environment` always wins), and a region other than `na` or `eu` makes
`New` fail with `butterflymx.ErrUnknownRegion`. An empty `Region` is ignored (the default is `Production`).

`Authenticator.Logout` signs out: it invalidates the API token on the server and
then deletes the stored token and the in-memory copy. Deleting needs a store that
implements the optional `auth.TokenDeleter` interface (`Delete(ctx) error`);
`auth.NewFileTokenStore` and `auth.NewMemoryTokenStore` both do. If the server
call fails, the local token is still deleted and the error is returned. A store
that is not a `TokenDeleter` cannot be cleared by the `Authenticator`: discard
the stored token yourself.

```go
if err := a.Logout(ctx); err != nil {
	slog.Warn("sign-out incomplete", "err", err)
}
```

## API coverage

| Area | Methods | Confidence |
|---|---|---|
| Login and tokens (`auth`) | `StartLogin`, `CompleteLogin`, `Refresh`, `ExchangeCode`, `DenizenLogin`, `Logout`, `Regions`, `AuthCodeFlow`, `Authenticator` | Confirmed |
| 2FA by authenticator app, SMS or email | `StartLogin` (`WithMFAMethod`), `SwitchMFAMethod`, `ResendMFACode`, `CompleteLogin`, `MFAChallenge` | Confirmed |
| User and tenants | `CurrentUser`, `Tenants`, `Tenant` | Confirmed |
| Doors | `AccessPoints` | Confirmed |
| Unlock | `Unlock` | Confirmed |
| Guest passes | `CreateKeychain` (custom, recurring), `Keychain`, `Keychains`, `KeychainsSeq`, `DeleteKeychain` | Confirmed |
| Virtual keys | `AddVirtualKeys`, `RevokeVirtualKey` | Confirmed |
| Delivery passes | `CreateDeliveryPass`, `UpdateDeliveryPass`, `ExtendDeliveryPass` | Confirmed |
| History | `DoorReleases`, `Calls`, `Messages` (lazy `iter.Seq2` pagination) | Confirmed |
| Smart and remote locks | `SmartLocks`, `RemoteLocks` | Unverified |
| Push devices | `RegisterPushDevice`, `TouchPushDevice`, `DeletePushDevice` | Confirmed |
| Other | `BLECredentials`, `LPRSettings` (data only; Bluetooth unlocking is out of scope) | Confirmed |

## Errors

Every failed API operation returns a `*butterflymx.Error` (use `errors.As` for
the HTTP status, JSON:API or GraphQL error details and a truncated body). Test
for the category with `errors.Is`:

```go
_, err := c.Keychain(ctx, id)
switch {
case errors.Is(err, butterflymx.ErrNotFound):
case errors.Is(err, butterflymx.ErrValidation): // 400 and client-side validation
case errors.Is(err, butterflymx.ErrRateLimited):
case errors.Is(err, auth.ErrReauthRequired): // refresh token rejected and no Relogin
}
var apiErr *butterflymx.Error
if errors.As(err, &apiErr) {
	slog.Error("api call failed", "op", apiErr.Op, "status", apiErr.StatusCode)
}
```

The server reports validation failures as HTTP 400 with one entry per problem
in `APIErrors`, each carrying only `Source.Pointer` (for example
`/data/attributes/ends_at`) and `Detail` (for example "cannot exceed 365 days
from start date"). An error page that is HTML rather than JSON (such as the 404
for an unknown route) is reported as an `*Error` with an "unexpected HTML
response" message and no `APIErrors`.

Sentinels: `ErrUnauthorized` (401), `ErrForbidden` (403), `ErrNotFound` (404),
`ErrConflict` (409), `ErrValidation` (400), `ErrRateLimited` (429),
`ErrServer` (5xx), `ErrNotSupported`, plus `ErrInvalidID` and `ErrIDType` for
malformed or wrongly typed global IDs (returned before any request is sent).

`auth` has its own: `ErrInvalidCredentials`, `ErrInvalidMFACode`,
`ErrMFAExpired`, `ErrMFAMethodUnsupported`, `ErrReauthRequired`,
`ErrLoginFlowChanged`, `ErrStateMismatch` and `ErrTokenConflict`.
Unexpected HTTP responses during login are an `*auth.Error`.

## Retries and idempotency

The client retries only requests that are safe to repeat: `GET`, `DELETE` and
GraphQL queries, on network errors, 5xx and 429, with jittered exponential
backoff that honors `Retry-After` and the context. Tune it with
`Options.Retry` (`RetryPolicy`: 4 attempts, 250 ms base and 5 s cap by
default). A 401 triggers one token refresh and one retry of any request.

Requests that create or trigger something are **never** retried:
`CreateKeychain`, `CreateDeliveryPass`, `AddVirtualKeys` and `Unlock`. A
replay after a timeout could create a second pass, email or text a guest
twice, or open a door twice.

After an ambiguous failure of a create (a timeout, a dropped connection, a
5xx), the pass may or may not exist. Reconcile before trying again: record
your intent (and the pass name) first, then list with `c.Keychains` (or
`KeychainsSeq`) for the tenant and look for a pass with that name and
schedule. Create again only if none is there, and `DeleteKeychain` any
duplicate.

## Testing with `butterflymxtest`

`butterflymxtest` is a public, stateful, in-memory fake of the accounts host,
API host and unlock service, seeded with a resident, one tenancy and a few
doors and passes. It speaks the wire protocol only (it does not import this
module's client), so it also checks the client independently. It serves plain
HTTP; `Environment.Validate` allows that for loopback hosts only.

```go
now := time.Now()
clock := func() time.Time { return now }

srv := butterflymxtest.NewServer(
	butterflymxtest.WithClock(clock),
	butterflymxtest.WithTokenTTL(time.Hour),
	butterflymxtest.WithAPITokenTTL(time.Hour),
)
defer srv.Close()

// Accounts, API and unlock service are all the fake. AuthConfig derives the
// matching auth.Config, so the login and the client cannot disagree.
env := butterflymx.LocalEnvironment(srv.URL())
cfg := env.AuthConfig()
cfg.HTTPClient = srv.Client()
cfg.Now = clock // token times follow the fake's clock

res, err := auth.StartLogin(ctx, cfg, butterflymxtest.DefaultEmail, butterflymxtest.DefaultPassword)
if err != nil {
	t.Fatal(err)
}
tok, err := auth.CompleteLogin(ctx, cfg, res.Challenge, srv.CurrentTOTP())
if err != nil {
	t.Fatal(err)
}

store := auth.NewMemoryTokenStore(tok)
c, err := butterflymx.New(butterflymx.Options{
	Environment: env,
	Auth:        auth.NewAuthenticator(auth.AuthenticatorConfig{Config: cfg, Store: store}),
	HTTPClient:  srv.Client(),
})

// Expiry tests need no sleeping: move the shared clock. The access token
// and API token will expire, so the next call refreshes them (and stores
// the rotated token).
now = now.Add(2 * time.Hour)
_, err = c.CurrentUser(ctx)

srv.FailNext("GET", "/v3/", 503, 1) // inject one failure; the client retries it
```

`Config.Now` and `butterflymxtest.WithClock` take the same kind of function, so
one clock drives the server's expiry and the library's token times. Without
`Config.Now`, the library uses the real time, and a fake whose clock is ahead
or behind it will disagree with the library about whether a token has expired.

Useful helpers: `IssueAPIToken` and `IssueOAuthToken` (skip the login flow),
`RevokeAPITokens` and `RevokeRefreshTokens` (force re-auth paths), `Seed`
(IDs of the seeded world), `Keychains`, `SentDeliveries`, `Unlocks` and
`Requests` (inspect what happened), `AddDoorRelease`, and the options
`WithClock`, `WithoutMFA`, `WithLastMFAMethod`, `WithMFASendOnGET`,
`MFADeliveries` and `LastMFACode` (read the SMS or email codes the fake
"sent"), `WithTokenTTL`, `WithAPITokenTTL` and
`WithPageSize`.

To check what the server says about requests the library would refuse, for
example a pass that ends before it starts, set `Options.SkipClientValidation`.
It turns off the client's pre-flight checks (schedule and recipient validation,
required names and doors) so the invalid request is sent as is. It is for
probing the API and for tests only: against the real service, such requests can
create passes and send messages. A request the server rejects still returns the
usual `*butterflymx.Error`.

## CLI

`cmd/bmx` is a small developer CLI for signing in and probing the API from a
terminal (`go run ./cmd/bmx login`; add `--mfa-method sms` or `email` to get
the code by text or email, and type `resend` or another method at the prompt).
Without `--env` or a URL override, it picks the environment from the region
saved in the token, so an EU account works without flags. It is meant for
development and experiments, not as a supported end-user tool; run it with
`-h` for the current commands.

## Development

```sh
go vet ./...
go test -race ./...
```

Tests run against `butterflymxtest` and recorded fixtures and never touch the
real API. Use `bmx probe` for manual checks against the real service.

The fixtures in [`testdata/`](testdata/README.md) are pseudonymized exchanges
from a mitmproxy capture of the official iOS app: names, IDs, PINs, tokens and
contact details are replaced consistently. The API was derived from that
capture plus prior public reverse-engineering notes. Read
[`API_SPEC.md`](API_SPEC.md) for the specification.

## Security notes

- OAuth tokens, API tokens and refresh tokens give full access to the account.
  Keep them out of logs, URLs and error reports. `*auth.Token` redacts itself
  via `String` and `LogValue`, but never log its fields (such as
  `AccessToken`) directly.
- An `MFAChallenge` is as sensitive as a session: it holds cookies and the
  PKCE verifier. Encrypt it and expire it quickly.
- Passwords are used once and never stored by this library.
- PINs are redacted when printed or logged (`PIN` implements `slog.LogValuer`
  and `fmt.Formatter`); call `PIN.Reveal` deliberately, only to show the guest
  or the resident. `PushDevice` likewise hides its push tokens.
- Error values carry a truncated response body and URLs without secrets, but
  review what you forward to third-party error trackers.

## License

[MIT](LICENSE). This software is provided as is, without warranty, and
without any affiliation with or endorsement by ButterflyMX. "ButterflyMX" is a
trademark of its owner.
