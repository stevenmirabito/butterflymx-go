# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-12

Supports the accounts login ButterflyMX deployed in November 2026. The previous
login no longer exists, so v0.1.0 cannot sign in. The API may change before v1.0.0.

### Fixed

- Sign-in works again with the accounts app ButterflyMX deployed in November
  2026, which replaced the Rails login: `StartLogin` failed with
  `ErrLoginFlowChanged` ("login form not found"). The flow was captured from
  production (see `API_SPEC.md` §3):
  - The login form is posted with `_csrf_token`, `return_to`, `email`,
    `password` and `commit` as a plain form (no `X-CSRF-Token`, no Turbo).
  - A wrong password is a `303` back to the login page, which shows
    "Invalid email or password"; it is still `ErrInvalidCredentials`, and a
    bounce back without that message is `ErrLoginFlowChanged`.
  - The two-factor pages moved to `/login/two_factor_authentication`. The
    method picker is a list of links rather than forms, and following one
    chooses the method. A wrong code re-renders the challenge page with
    "Invalid verification code".
  - When the server has no default method it lands on the picker;
    `StartLogin` then takes `WithMFAMethod`, or else the authenticator app
    (which sends nothing), then email, then SMS.
  - The final authorize hop is a "Returning to app…" page that links to the
    app, not a redirect; both are accepted.
- `ErrLoginFlowChanged` messages describe the page by its visible text and
  form actions instead of the start of its HTML, which was only scripts.
- Asking for a method the account does not have (`WithMFAMethod`,
  `SwitchMFAMethod`) returns `ErrMFAMethodUnsupported` when the picker was
  recognized, not `ErrLoginFlowChanged`.
- A challenge stays usable after a failed step: the session cookies the server
  issued are kept on every error of `CompleteLogin` and `ResendMFACode`, and
  after a failed `SwitchMFAMethod` the form tokens follow the rotated
  `_csrf_token` cookie (the server double-submits it).
- Login requests are refused unless scheme and host match the accounts URL
  (a form action could downgrade to HTTP), and the app redirect is matched
  by scheme, authority and path instead of by string prefix.
- Error text of the headless login no longer reflects server text where it is
  not needed (see "Error text" in the `auth` package documentation):
  - The OAuth leg (code exchange, region discovery, denizen login) reports
    operation, status and an allowlisted OAuth error code only; `Error.Description`
    and `Error.Body` are empty there, and a transport failure names only its class.
    The original error stays reachable with `errors.Is` and `errors.As`.
  - Changed-flow errors keep a short excerpt of the page's visible text and its form
    paths (never markup, scripts, embedded data or text the user does not see, such as
    templates and hidden elements), with the submitted secrets (also
    URL-encoded), email addresses, phone numbers, digit runs of five or more and long
    tokens masked.
  - Login request failures show the URL without query, userinfo and fragment, and a
    masked cause; server-supplied method names are echoed only if they are plain
    identifiers and OAuth error codes only if they are standard ones; `MFAChallenge.UnmarshalBinary` does not quote the
    state it could not decode.
  - Outside the headless login, `Regions`, `DenizenLogin` and `Logout` errors scrub
    the token they were called with (also as a JSON serializer escapes it) and long
    opaque values before cutting the body; a JSON body that does not decode is not shown.

### Added

- `MFAChallenge.Offered`: the methods the account's method picker offered, so a
  UI need not offer a method the account lacks. It is nil (unknown) while the
  server has chosen a default method; it is set when the login lands on the
  picker and by `SwitchMFAMethod`, also when that fails with
  `ErrMFAMethodUnsupported`.

### Changed

- `MFAChallenge` blobs are version 3. Challenges from earlier versions (1 and
  2) are rejected by `UnmarshalBinary`: their sessions were on the old server.
- `butterflymxtest` emulates the new accounts app (new paths, `identity_session`
  and double-submit CSRF cookies, picker links, "Returning to app" page).
  Added `WithMFAPickerLanding`. The recorded Rails login pages were removed
  from `testdata/accounts`.

### Known limitations

These parts of the new login were not observed in the production captures
(2026-11-12) and are handled from the old behavior or in several shapes:

- The response to "Resend code".
- The response to a wrong code for SMS and email (the authenticator app's is
  captured: the challenge page again, with "Invalid verification code").
- A login without two-factor authentication.
- Whether following a picker link, or loading an SMS or email challenge page,
  sends the code (assumed, as before), and whether an earlier code stays valid
  after a resend.
- `Offered` is nil until the method picker has been seen; when the server picks
  a default method, the library cannot tell what other methods the account has.

## [0.1.0] - 2026-11-12

Initial release. The API may change before v1.0.0.

### Added

- Client (`butterflymx`): `Client` with `Options` (environment, token provider,
  HTTP client, logger, user agent, retry policy), environment presets
  (`Production`, `ProductionEU`, `Staging`, `Sandbox`), typed IDs
  (`GlobalID`, `ID`), and a `Date`/`TimeOfDay` model for building-local time.
- Errors: `*Error` with HTTP status, JSON:API and GraphQL details, and
  `errors.Is` sentinels (`ErrUnauthorized`, `ErrForbidden`, `ErrNotFound`,
  `ErrConflict`, `ErrValidation`, `ErrRateLimited`, `ErrServer`,
  `ErrNotSupported`, `ErrInvalidID`, `ErrIDType`).
- Transport: automatic retries with jittered backoff for idempotent requests
  only, a single re-authentication retry after a 401, and no automatic retry
  for creates or unlock.
- Tenants and doors: `CurrentUser`, `Tenants`, `Tenant`, `AccessPoints`.
- Unlock: `Unlock` through the unlock service.
- Guest passes: `CreateKeychain` with custom and recurring schedules and
  email or SMS recipients, `Keychain`, `Keychains`, `KeychainsSeq`,
  `DeleteKeychain`, `AddVirtualKeys`, `RevokeVirtualKey`.
- Delivery passes: `CreateDeliveryPass`, `UpdateDeliveryPass`,
  `ExtendDeliveryPass`. A delivery pass always covers every guest-pass door.
- Guest passes are immutable (the API has no edit endpoint): to change one,
  create a new pass and delete the old one.
- Validation errors are HTTP 400 with `source.pointer` and `detail` per
  problem (`ErrValidation`); a pass can last at most 365 days. A non-JSON
  (HTML) error page, such as the 404 for an unknown route, yields a clean
  `*Error` whose message does not include the page.
- History: `DoorReleases`, `Calls` and `Messages` as lazy `iter.Seq2`
  iterators.
- Locks: `SmartLocks` and `RemoteLocks` (fields unverified, modeled from the
  app's GraphQL fragments), `BLECredentials`, `LPRSettings`.
- Push devices: `RegisterPushDevice`, `TouchPushDevice`, `DeletePushDevice`.
- Escape hatches: `GraphQL` and `REST`.
- Secret hygiene: `PIN` is redacted by `fmt` and `slog`; `PushDevice` omits
  push tokens when printed or logged.
- Authentication (`auth`): headless login with email, password and a second
  factor (authenticator app, SMS or email) as a resumable two-step flow
  (`StartLogin`, `CompleteLogin`, serializable `MFAChallenge` with a TTL,
  `Method`, `Destination` and `CanResend`), `WithMFAMethod` to choose the
  method up front, `SwitchMFAMethod` ("Verify another way"), `ResendMFACode`,
  `ParseMFAMethod` and `ErrMFAResendUnsupported`. The server picks the last
  used method by default; SMS and email make it send a code. The
  `WithMFAMethod` shortcut is unverified against production and falls back to
  the app's sequence. Also browser-assisted
  `AuthCodeFlow`, token `Refresh` with rotation, `DenizenLogin`, `Logout`,
  `Regions`, and an `Authenticator` that keeps tokens fresh and persisted in a
  `TokenStore` using compare-and-swap (`MemoryTokenStore`, `FileTokenStore`).
- Testing (`butterflymxtest`): a public, stateful fake ButterflyMX server
  (login with TOTP, SMS or email codes, tokens, GraphQL, passes, delivery
  passes, unlock) with fault injection (`FailNext`), clock control, request recording and a
  pseudonymized seed world.
- Documentation: reverse-engineered API specification and
  pseudonymized fixtures in `testdata/`.
- Regions: `EnvironmentForRegion` ("na" or "eu"), `ErrUnknownRegion` and
  `Options.Region`, so that `auth.Token.Region` selects the API host.
- Environments: `LocalEnvironment(baseURL)` for the fake server, a proxy or any
  single-host setup, `Environment.AuthConfig()` to derive the matching
  `auth.Config`, and `auth.ConfigFor(accountsURL, apiURL)` (the presets are
  built with it).
- Clock: `auth.Config.Now` and `auth.AuthenticatorConfig.Now` inject the time
  source for challenge ages, `MFAChallengeTTL` and token times, so expiry can be
  tested without sleeping.
- Sign-out: `Authenticator.Logout` invalidates the API token on the server and
  deletes the stored token and the cached copy; `auth.TokenDeleter` is the
  optional store interface it uses (`Delete` on `FileTokenStore` and
  `MemoryTokenStore`).
- `Options.SkipClientValidation` turns off the client's pre-flight request
  checks, for probing the API and for tests only.
- Developer CLI: `cmd/bmx` for signing in and probing the API. `login` accepts
  `--mfa-method app|sms|email` and, at the code prompt, `resend` or another
  method name. `logout` uses `Authenticator.Logout`. Without `--env` or a URL
  override, the region saved in the token selects the environment, so an EU
  account works without flags. The `validation` probe uses `CreateKeychain` with
  `SkipClientValidation`.

### Known limitations

- Smart lock and remote lock fields are unverified.
- Throttling, attempt limits and lockout for two-factor codes are unknown.
  Loading an SMS or email challenge page sends a code by itself, so
  `StartLogin` triggers one when the server's default method is
  SMS or email.
- Only the production environment is confirmed from captured traffic.
