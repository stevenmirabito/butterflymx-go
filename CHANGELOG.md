# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Initial pre-release. The API may change before v1.0.0.

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
