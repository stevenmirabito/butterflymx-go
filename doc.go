// Package butterflymx is an unofficial Go client for the ButterflyMX resident
// API, focused on granting and revoking guest access to buildings on behalf of
// a resident.
//
// ButterflyMX does not publish a public API. This package uses the same
// private endpoints as the official mobile apps, which may change without
// notice. It is not affiliated with or endorsed by ButterflyMX. Use it only
// with your own account and for doors you are authorized to open. The API it
// targets is described in API_SPEC.md in the repository.
//
// # Concepts
//
//   - A [Tenant] is a resident's tenancy: a [Unit] in a [Building]. Most
//     operations are scoped to one, see [Client.Tenants].
//   - An [AccessPoint] is a door. Only doors for which
//     [AccessPoint.SupportsVirtualKeys] is true can be part of a guest pass.
//   - A [Keychain] is a guest pass: a time-bounded grant of access to a set of
//     doors. Create one with [Client.CreateKeychain] and remove it with
//     [Client.DeleteKeychain]. Guest passes are immutable: to change one,
//     create a new pass and delete the old one. Its kind ([KindCustom], [KindRecurring] or
//     [KindDeliveryPass]) says how it is scheduled.
//   - A [VirtualKey] is one credential inside a keychain, issued to one
//     [Recipient]. The guest opens the door with its [PIN] or QR code, and
//     ButterflyMX sends it to the recipient by email or SMS. Add keys with
//     [Client.AddVirtualKeys] and revoke one with [Client.RevokeVirtualKey].
//   - A delivery pass is a one-time keychain without recipients, made with
//     [Client.CreateDeliveryPass] and changed with [Client.UpdateDeliveryPass]
//     or [Client.ExtendDeliveryPass]. It always covers every door that
//     supports virtual keys; the door list cannot be chosen.
//   - The server rejects an invalid pass with HTTP 400, which maps to
//     [ErrValidation]; [Error.APIErrors] carries one entry per problem with
//     Source.Pointer and Detail. A pass can last at most 365 days (see
//     [Building.VirtualKeysDurationPeriod]).
//
// Besides passes, the client can open a door ([Client.Unlock]), read history
// ([Client.DoorReleases], [Client.Calls], [Client.Messages]) and list locks
// ([Client.SmartLocks], [Client.RemoteLocks]). [Client.GraphQL] and
// [Client.REST] are escape hatches for calls the typed API does not cover.
//
// # Authentication
//
// A [Client] needs a [TokenProvider], which supplies the API bearer token and
// drops it when the server rejects it. The usual choice is an
// [github.com/stevenmirabito/butterflymx-go/auth.Authenticator], which keeps
// OAuth and API tokens fresh and persisted in a token store. Package auth also
// implements the login itself, including two-factor authentication by
// authenticator app, SMS or email as a two-step flow that can be resumed
// across requests (with options to choose the method, switch it and resend
// the code). [StaticAPIToken] is a provider for a fixed token.
//
// An account lives in a region ("na" or "eu"; auth.Token.Region records it)
// and the regions have different API hosts. Pass the region in [Options.Region]
// (see [EnvironmentForRegion]) or choose an [Environment] explicitly.
// [Environment.AuthConfig] derives the auth configuration from an environment
// so that the login and the client agree.
//
// # Testing
//
// The butterflymxtest package is a stateful fake server. Point a client at it
// with [LocalEnvironment], build the login configuration with
// [Environment.AuthConfig], and set auth.Config.Now (with butterflymxtest's
// WithClock) to test token expiry without waiting. [Options.SkipClientValidation]
// turns off the client's own request checks, to see how the server answers
// invalid requests; it is for probing and tests only.
//
// # IDs
//
// The GraphQL API identifies nodes with a [GlobalID] such as
// "prod-access_point-70001": an environment prefix, a type tag and a number.
// The REST API uses the bare number as an [ID], which is a decimal string on
// the wire. The two are related: [GlobalID.As] extracts the number if the type
// matches, and [AccessPoint.RESTID] returns the REST ID of a door. Methods take
// the form their endpoint uses: tenants, doors and the unlock service take a
// [GlobalID], while keychains and virtual keys take an [ID]. A [GlobalID] of
// the wrong type is rejected with [ErrIDType] before any request is sent.
//
// # Time
//
// Two kinds of time appear in the API and are kept apart in the types.
// Instants (a [CustomSchedule], [Keychain.StartsAt], history timestamps) are
// [time.Time] values and are sent as UTC. Building-local values, which are a
// calendar [Date] and a wall-clock [TimeOfDay] with no zone, are used by a
// [RecurringSchedule] and by [Keychain.StartDate] and friends. They are
// interpreted in the zone of the building ([Building.TimeZone], loaded with
// [Building.Location]), not in the zone of the caller or the server. Use
// [DateOf] and [TimeOfDay.On] to convert.
//
// # Errors
//
// Failed API operations return a [*Error], which carries the HTTP status and
// any JSON:API or GraphQL error details. Match the category with [errors.Is]
// against [ErrUnauthorized], [ErrForbidden], [ErrNotFound], [ErrConflict],
// [ErrValidation], [ErrRateLimited], [ErrServer] and [ErrNotSupported].
// Malformed identifiers produce [ErrInvalidID] or [ErrIDType]. Errors from
// the login flow are sentinels in package auth.
//
// # Retries
//
// Idempotent requests (GET, DELETE and GraphQL queries) are retried on network
// errors, 5xx and 429, see [RetryPolicy]. Requests that create something or
// open a door ([Client.CreateKeychain], [Client.CreateDeliveryPass],
// [Client.AddVirtualKeys], [Client.Unlock]) are never retried, so that a
// timeout cannot produce a duplicate pass or a second message to a guest.
// After an ambiguous failure, reconcile with [Client.Keychains].
//
// # Confidence
//
// Endpoints were confirmed from captured traffic or live probes. The smart and
// remote lock types are modeled without real data. Whether the server throttles
// or locks out repeated two-factor attempts is unknown. Secrets are redacted in logs: [PIN] hides its digits and
// the auth package's Token hides its tokens.
package butterflymx
