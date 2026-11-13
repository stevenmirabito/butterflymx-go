// Package auth implements ButterflyMX resident authentication: the OAuth 2.0
// authorization-code flow with PKCE (including the web login form and the
// second factor), token refresh, the "denizen" login that turns an OAuth token
// into an API token, and an [Authenticator] that keeps a token fresh and
// persisted in a [TokenStore].
//
// # Two-factor authentication
//
// [StartLogin] checks the password. When the account requires a second factor
// it returns an [MFAChallenge] for [CompleteLogin]. The server decides the
// first method: the one used by the account's last successful login, so it
// may be an authenticator app, a text message (sms) or an email. StartLogin
// follows that choice exactly as the app does, which for sms and email
// means the server sends a code; [MFAChallenge.Method] and
// [MFAChallenge.Destination] (a masked phone number for sms) tell the user
// where to look. Pass [WithMFAMethod] to ask for another method up front
// without loading the default challenge page, which could itself send a text
// or email.
//
// After StartLogin the challenge can change method with [SwitchMFAMethod]
// ("Verify another way") and, for sms and email, request another code with
// [ResendMFACode]; check [MFAChallenge.CanResend]. A wrong code makes
// [CompleteLogin] return [ErrInvalidMFACode] and refresh the challenge in
// place. Whenever the challenge changes, marshal it again
// ([MFAChallenge.MarshalBinary]): it holds the session cookies, the page's
// per-form CSRF tokens and the PKCE verifier, so keep it private and
// short-lived ([MFAChallengeTTL]). [ParseMFAMethod] turns user input such as
// "text" or "app" into an [MFAMethod].
//
// # Environments, clock and sign-out
//
// [Production], [ProductionEU], [Staging] and [Sandbox] are [ConfigFor] of
// their URLs; use [ConfigFor] for a local fake, a proxy or a future region
// (the root package's Environment.AuthConfig builds on it). [Config.Now]
// injects a clock used for challenge ages, [MFAChallengeTTL] checks and the
// times in [Token]; [AuthenticatorConfig.Now] takes precedence for an
// [Authenticator]. [Authenticator.Logout] invalidates the API token on the
// server and deletes the stored token when the [TokenStore] is a
// [TokenDeleter] (both built-in stores are).
//
// # Error text
//
// Errors from the headless login are meant to be logged, so they follow a
// policy. The threat model is ButterflyMX accidentally putting something
// private into a page, not a server built to trick the library: pattern
// matching cannot stop the latter, so nothing relies on it.
//
//   - The OAuth leg (code exchange, region discovery, denizen login) reports
//     only the operation, the HTTP status and an allowlisted OAuth error code
//     ([Error.Description] and [Error.Body] are empty), and a transport failure
//     names only its class (timed out, canceled, network error, unexpected
//     response). The original error stays reachable with errors.Is and
//     errors.As.
//   - A page the library does not recognize ([ErrLoginFlowChanged]) is
//     described by about 300 characters of its visible text and its form
//     targets (paths only; a malformed action is not shown): that is what
//     makes a changed flow diagnosable. Markup, scripts, embedded data and
//     text the user does not see (templates, noscript fallbacks, hidden
//     elements) are never shown. The submitted email, password and code, URL-escaped forms
//     of them, email addresses, phone numbers, runs of five or more digits and
//     long opaque tokens are masked.
//     Anything else the page shows, such as a name or a masked phone number,
//     appears: treat these logs as containing provider page text. A call made
//     after StartLogin (SwitchMFAMethod, ResendMFACode) does not know the email
//     or password, since the library keeps no password and a challenge must not
//     hold one; it masks by pattern only.
//   - [Regions], [DenizenLogin] and [Logout] keep a short body in their errors,
//     scrubbed of the token they were called with: JSON is decoded and scrubbed
//     per string; JSON that does not decode (including one cut at the read
//     limit) is not shown.
//   - Request failures in the login pages show the URL without query, userinfo
//     and fragment, and the cause with the same masking.
//
// The flow is reverse-engineered from the official iOS app; see API_SPEC.md
// section 3. This package never stores passwords. It does not import the root
// butterflymx package; *[Authenticator] satisfies the root TokenProvider
// interface structurally.
package auth
