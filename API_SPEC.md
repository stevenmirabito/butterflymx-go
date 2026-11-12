# ButterflyMX API Specification (Unofficial)

## 0. About this document

This document describes the private HTTP API used by the ButterflyMX resident
mobile apps. The API is not published or supported by ButterflyMX and may
change without notice. All identifiers, names, PINs and tokens in examples are
placeholders.

Notation: `<angle brackets>` mark placeholders to be replaced with real values.

---

## 1. Concepts and domain model

| Term | Meaning |
|---|---|
| **User** | A ButterflyMX account. One user can have several tenants. |
| **Tenant** | A user's residency in one unit of one building. Most operations are scoped to a tenant. |
| **Unit** | An apartment or suite (`label`, `floorNumber`). |
| **Building** | A property. Has an IANA `timeZone` (e.g. `America/Los_Angeles`), which governs every building-local date and time (§7.2). |
| **Access point** | A door or gate (`name`, `online`, `openDuration` in seconds). Served by one or more devices. |
| **Device** | Physical hardware behind access points: intercom **panels** (`panels` in REST, `Intercom` in GraphQL) and **cloud access controllers** (`cloud_keyz_controllers` in REST, `CloudBasedAccessController` in GraphQL). |
| **Keychain** (a.k.a. *access code*, "pass") | A time-bounded **grant** tying a tenant to a set of access points. Kinds: `custom` (one continuous window), `recurring` (weekdays plus a daily window between two dates), and `delivery_pass` (a single virtual key with **no recipient**, valid for 30 days or until **first use**, for couriers; see §7.4a). |
| **Virtual key** | One **credential** inside a keychain, issued to one recipient. Has a 6-digit **PIN**, a **QR code** image URL, and a public **instructions URL**. ButterflyMX sends it to the recipient by **email or SMS**. |
| **Door release** | A log entry recording that a door was opened. |

**Guest access**: create a keychain for the chosen access points and time window,
with the guest as recipient. This one request creates the keychain *and* the
virtual key (§7.4). Show the returned PIN, QR code and instructions link to the tenant. To revoke it, delete the keychain, or delete just one virtual key.

```
User ──< Tenant >── Unit ── Building (timeZone)
           │
           ├──< AccessPoint ──< Device (panel | cloud controller)
           │
           └──< Keychain ──< VirtualKey ──< DoorRelease
                   │
                   └──< Device ("devices": panels + cloud_keyz_controllers)
```

---

## 2. Hosts and environments

| Purpose | Production (NA) | Production (EU) | Staging NA | Sandbox |
|---|---|---|---|---|
| Accounts / OAuth | `https://accounts.butterflymx.com` | same host | `https://accounts.na.staging.butterflymx.com` | `https://accounts.na.sandbox.butterflymx.com` |
| Main API (REST `/v3`, `/mobile/v4`, GraphQL, denizen) | `https://api.butterflymx.com` | `https://eu.api.butterflymx.com` | `https://api.na.staging.butterflymx.com` | `https://api.na.sandbox.butterflymx.com` |
| Unlock service | `https://api.unlock.prod.butterflymx.com` | — | — | — |
| Guest-facing pages | `https://user.butterflymx.com` | — | n/a | n/a |
| QR images | `https://s3.dualstack.us-east-1.amazonaws.com/bmx-rails-production/…` | n/a | n/a | n/a |

**Region discovery.** The official app calls this right after the
token exchange, using the **OAuth** access token:

```
GET https://accounts.butterflymx.com/api/mobile/regions
Authorization: Bearer <oauth access token>

200 {"regions": ["na"]}          // "na" | "eu"; use regions[0], default "na"
```

---

## 3. Authentication

There are two token layers. **The official app uses the OAuth token for exactly
two calls**: region discovery and the denizen login. **Every other API call
uses the denizen API token.**

```
email + password ──(§3.2 /login)──▶ [2FA §3.3] ──▶ authorization code
authorization code ──(§3.4 PKCE exchange)──▶ OAuth access token (JWT, 24 h) + refresh token
OAuth access token ──(§3.6 denizen login)──▶ API token (opaque)
API token ──▶ GraphQL, /v3, /mobile/v4, unlock service
```

| Token | Format | Lifetime | Used for |
|---|---|---|---|
| OAuth access token | JWT (3 segments, about 370 chars) | `expires_in: 86400` | `/api/mobile/regions`, `/denizen/v1/login` |
| OAuth refresh token | opaque | may be replaced on use (§3.5) | `/oauth/token` refresh |
| OAuth `id_token` | JWT (OIDC) | n/a | not needed |
| API token | opaque, about 342 chars, no dots | — | everything else |

### 3.1 OAuth client (resident mobile app)

The official app uses:

| Parameter | Value |
|---|---|
| `client_id` | `0e3aeeb7cec2782b9fb21352a4349a44405ed5d7674072416b6481d51abfd6b6` (public, PKCE, no secret) |
| `redirect_uri` | `com.butterflymx.oauth://oauth` |
| `scope` | `openid profile` |
| PKCE | `S256` (43-char base64url verifier) |
| Extra authorize params | `nonce=<random>`, `state=<random>`, `prompt=login` |

The accounts site is a Rails application that uses Turbo (Hotwire). Its session
cookie, `_accounts_session`, is re-issued on responses, so a cookie jar must be
kept for the whole flow.

### 3.2 Login step 1: email and password

1. **Authorize**

   ```
   GET /oauth/authorize?client_id=…&redirect_uri=com.butterflymx.oauth://oauth
       &response_type=code&scope=openid profile&code_challenge=…
       &code_challenge_method=S256&nonce=…&state=…&prompt=login
   → 302 Location: https://accounts.butterflymx.com/login/new     (sets _accounts_session)
   ```

2. **Login page**: `GET /login/new` → `200 text/html`. Contains:
   - `<meta name="csrf-token" content="…">`
   - `<form action="/login" method="post">` with inputs `authenticity_token`
     (hidden), `login[email]`, `login[password]` and `commit` (value
     `Sign in with email`)
   - Alternative SSO forms (`/sso/microsoft`, `/sso/google`), which are out of
     scope.

3. **Submit credentials**

   ```
   POST /login
   Content-Type: application/x-www-form-urlencoded;charset=UTF-8
   Accept: text/vnd.turbo-stream.html, text/html, application/xhtml+xml
   X-CSRF-Token: <meta csrf-token>

   authenticity_token=<form token>&login[email]=<email>&login[password]=<password>&commit=Sign in with email
   ```

   Do **not** follow redirects automatically. Outcomes:

   | Response | Meaning |
   |---|---|
   | `303 Location: /sessions/two_factor_authentication/new?type=<method>` | Password OK and 2FA required → §3.3 |
   | `200` turbo-stream with `location="/oauth/authorize?…"` | Password OK, no 2FA → step 4 |
   | HTML containing the login form again, with an error message | Wrong email or password |

4. **Finish authorization**: `GET {location}` with `&amp;` decoded to `&`
   → `302 Location: com.butterflymx.oauth://oauth?code=<code>&state=<state>`.
   Check that `state` matches and take `code`.

### 3.3 Login step 2: two-factor authentication

The account's 2FA configuration can be read later through GraphQL
`currentUser.twoFactorAuthenticationConfig { enabled required types }`.
`types` values: `EMAIL`, `SMS`, `AUTHENTICATOR_APP`.

**The server chooses the first method.** `POST /login` redirects to
`/sessions/two_factor_authentication/new?type=<method>`, where `<method>` is
one of `authenticator_app`, `sms` and `email`. It is the method used for the
**last successful login**, so clients must not assume `authenticator_app`.

All three methods use the same verify form and endpoint; only `type` differs.

1. **Challenge page**: `GET /sessions/two_factor_authentication/new?type=<method>` → `200 text/html`. It contains `<meta name="csrf-token">` and:

   ```html
   <form action="/sessions/two_factor_authentication" method="post">
     <input type="hidden" name="authenticity_token" value="…">
     <input type="hidden" name="type" value="authenticator_app|sms|email">
     <input type="text"   name="code" autocomplete="one-time-code">
     <input type="submit" name="commit" value="Use code">
   </form>
   <a href="/sessions/two_factor_authentication">Verify another way</a>
   ```

   | Method | Heading | Body text | Resend form |
   |---|---|---|---|
   | `authenticator_app` | "Verify with an authenticator app" | "Enter the verification code the authenticator app provides" | none |
   | `sms` | "Verify with text message" | "A 6-digit code has been sent to your phone number `******NNNN`" (last 4 digits shown) | yes |
   | `email` | "Verify with an Email" | "A 6-digit code has been sent to your email" (no address shown) | yes |

   **Loading this page by GET sends the code.** After `POST /login` redirects to
   `…/new?type=sms` or `type=email`, the `GET` of that page itself texts or
   emails a code, with no further request. A client that follows the login
   redirect to an SMS or email challenge has therefore already triggered a code
   and must not ask for another right away. The authenticator-app page sends
   nothing.

2. **Switching method ("Verify another way")**

   ```
   GET /sessions/two_factor_authentication                      → 200 html: method picker
   ```

   The picker has **one form per method**, each a one-button form with its **own**
   `authenticity_token`. **CSRF tokens are per form**: none of
   them equals the page's `<meta name="csrf-token">`, and a POST uses the
   token of the form it submits:

   ```html
   <form action="/sessions/two_factor_authentication/new?type=email" method="post">…<input type="hidden" name="authenticity_token" value="…"></form>
   <form action="/sessions/two_factor_authentication/new?type=sms" method="post">…</form>
   <form action="/sessions/two_factor_authentication/new?type=authenticator_app" method="post">…</form>
   ```

   **Choosing a method sends the code** for `sms` and `email`:

   ```
   POST /sessions/two_factor_authentication/new?type=sms        form: authenticity_token=<token of the sms form>
   → 200 html: the challenge page (as above) for that method
   ```

3. **Resend** (sms and email only) is a form on the challenge page:

   ```
   POST /sessions/two_factor_authentication/new?type=sms        form: authenticity_token=<token of the resend form>&context=resend
   → 200 html: the challenge page again, with a notice "A code has been sent to your phone number."
   ```

   **A resend does not invalidate the earlier code**: the first code still
   works afterwards.

   The picker and resend POSTs are plain form posts: the official app sends
   **no** `X-CSRF-Token` header and a browser-style `Accept` for them.

4. **Submit the code**

   ```
   POST /sessions/two_factor_authentication
   Content-Type: application/x-www-form-urlencoded;charset=UTF-8
   Accept: text/vnd.turbo-stream.html, text/html, application/xhtml+xml
   X-CSRF-Token: <meta csrf-token>

   authenticity_token=<form token>&type=<method>&code=<6 digits>&commit=Use code
   ```

   | Response | Meaning |
   |---|---|
   | `200` turbo-stream: `<turbo-stream location="/oauth/authorize?…(HTML-escaped)…" action="redirect_to"><template></template></turbo-stream>` | Success → §3.2 step 4 |
   | `422 text/html`: the challenge page re-rendered with "Two factor authentication failed." / "Invalid code, please try again or request a new code." and a **fresh** `authenticity_token` | Wrong code. Retry using the **new** CSRF token. Same for all three methods. |

   The custom Turbo action is `redirect_to`, not the standard `redirect`, so
   parse the `location` attribute regardless of `action`.

5. **There is no "remember this device" option**: each login requires 2FA.

### 3.4 Authorization code exchange

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

code=<code>&code_verifier=<verifier>&redirect_uri=com.butterflymx.oauth://oauth
&client_id=<client_id>&grant_type=authorization_code
```

```json
200
{
  "access_token": "<JWT>",
  "token_type": "Bearer",
  "expires_in": 86400,
  "refresh_token": "<opaque>",
  "scope": "openid profile",
  "created_at": 1794000000,
  "id_token": "<JWT>"
}
```

### 3.5 Refresh

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=<rt>&client_id=<client_id>
```

- The response may contain a new `refresh_token`, in which case it replaces
  the old one.
- An `invalid_grant` error means a new login is required.

### 3.6 Denizen login: OAuth token → API token

```
POST https://api.butterflymx.com/denizen/v1/login
Content-Type: application/json

{
  "access_token": "<oauth access token>",
  "device": {
    "platform": "ios",
    "version": "1001.125.2",
    "locales": ["en-US"],
    "token": "<APNs push token>",          // optional
    "voip_token": "<PushKit VoIP token>"   // optional
  }
}

200 {"token": "<api token>"}
```

The official app then registers its push device
(`POST /mobile/v4/users/devices`, §7.9).

### 3.7 Logout

```
DELETE https://api.butterflymx.com/denizen/v1/logout     Authorization: Bearer <api token>   → 200 (empty body, text/html)
```

The official app also deletes its push device (`DELETE /mobile/v4/users/devices/{id}` → 204).

### 3.8 Request headers

| Header | Value |
|---|---|
| `Authorization` | `Bearer <api token>` (or the OAuth token for §2 regions and §3.6) |
| `User-Agent` | Accounts web views: a mobile Safari UA. Alamofire calls: `butterflymx/1001.125.2 (com.butterflymx.butterflymx; build:1266; iOS 27.2.0) Alamofire/5.10.2`. URLSession calls: `butterflymx/1266 CFNetwork/3896.200.61 Darwin/27.2.0` |
| `Content-Type` | `application/json` (GraphQL, `/v3`, unlock), `application/x-www-form-urlencoded` (accounts, `/mobile/v4`) |
| `x-bmx-service` | `denizen-api` (GraphQL only) |
| `Accept` | `*/*`. GraphQL requests send `multipart/mixed;deferSpec=20220824,application/graphql-response+json,application/json` (Apollo). |
| `If-None-Match` | The official app sends ETags on `/v3` GETs and gets `304`. Optional. |

The official app does not send an `apollographql-client-name` header. Instead,
the Apollo client puts
`"extensions":{"clientLibrary":{"name":"apollo-ios","version":"2.4.0"}}` in the
GraphQL body. Both are optional.

---

## 4. Identifiers

| Format | Example | Used by |
|---|---|---|
| **Global ID** | `prod-tenant-8000001`, `prod-access_point-70001`, `prod-unit-2000001`, `prod-building-30001`, `prod-user-900000001`, `prod-cloud_based_access_controller-80001`, `prod-intercom-85001`, `prod-user_device_apple-13000001`, `prod-call-274000001` | GraphQL, unlock service |
| **Numeric ID** (JSON string) | `"8000001"`, `"70001"` | REST `/v3`, `/mobile/v4` |

- Format: `{env}-{type}-{number}`. `{type}` is snake_case and may contain
  underscores. Parse by splitting on the first `-` (env) and the **last** `-`
  (number).
- **The numeric part is the REST ID**: `prod-tenant-8000001`
  is `filter[tenant]=8000001`, and access point `prod-access_point-70001` is
  `{"type":"access_points","id":"70001"}`.
- GraphQL `AccessPoint.legacyId` returns that REST ID directly (`"70001"`).
- Type tags are not always spelled correctly. Door releases come back as
  `prod-door_relase-…`. Don't validate tags against a fixed list when
  decoding.
- Building `guid` is a different scheme (`prod-core-na-building-30001`).

---

## 5. GraphQL API

```
POST https://api.butterflymx.com/denizen/v1/graphql
Authorization: Bearer <api token>
Content-Type: application/json
x-bmx-service: denizen-api

{"operationName": "<Name>", "query": "<document>", "variables": {...}}
```

- Response: `{"data": ..., "errors": [...]}`.
- Pagination follows Relay: `after`, `pageInfo { hasNextPage endCursor }` and
  `nodes`. Cursors are opaque. Most are base64 offsets (`MQ` = 1, `MjA` = 20),
  while `doorReleases` uses base64 JSON (`occurredAt` + id), and `endCursor`
  can be `null` on an empty connection. The official app sends `"after": ""` for the
  first page.
- `__typename` appears on every selection (Apollo convention). It is optional.

Fragments below are abbreviated to the commonly used fields.

### 5.1 `CurrentUser`

```graphql
query CurrentUser { currentUser {
  id firstName lastName email phoneNumber avatarUrl contactPreference
  twoFactorAuthenticationConfig { enabled required types }   # types: EMAIL | SMS | AUTHENTICATOR_APP
} }
```

### 5.2 `Tenants`

```graphql
query Tenants($after: String) { tenants(after: $after) {
  pageInfo { hasNextPage endCursor }
  nodes {
    id firstName lastName name pinCode legacyPinCode inactiveAfter
    virtualKeyEnabled deliveryPassEnabled
    unit { id label floorNumber }                  # floorNumber is a string
    building {
      id guid name timeZone                        # IANA zone, e.g. "America/Los_Angeles"
      capabilities                                 # e.g. VIRTUAL_KEYS_ENABLED, DOOR_PIN_ENABLED, DELIVERY_PASS_ENABLED, BLE_ACCESS_ENABLED
      virtualKeysDurationPeriod                    # int days (e.g. 365) = maximum pass length
      suspended
      address { country }
    }
  }
} }
```

### 5.3 `Tenant` (single)

`query Tenant($tenantId: ID!) { nodes(ids: [$tenantId]) { id ...TenantFragment } }`
uses the same fragment as §5.2.

### 5.4 `TenantAccessPoints`

```graphql
query TenantAccessPoints($ids: [ID!]!, $after: String) { nodes(ids: $ids) { id ... on Tenant {
  accessPoints(after: $after) {
    pageInfo { hasNextPage endCursor }
    nodes {
      id legacyId name openDuration online inOpenHours
      capabilities                                 # e.g. VIRTUAL_KEYS, DOOR_PINS, SWIPE_TO_OPEN, BLUETOOTH
      accessTimes       { from to days }           # "00:00".."00:00" + all days = always
      doorOpenSchedules { from to days }           # days: MONDAY..SUNDAY
      building { id timeZone }
      devices { nodes {
        ... on Intercom                    { id name serialNumber }
        ... on CloudBasedAccessController  { id name readerSerialNumbers }
      } }
    }
  }
} } }
```

### 5.5 History connections (`TenantDoorReleases`, `TenantCalls`, `TenantMessages`)

`query X($tenantIds: [ID!]!, $after: String) { nodes(ids: $tenantIds) { id ... on Tenant { <field>(after: $after) { pageInfo {…} nodes {…} } } } }`

| Field | Node fields |
|---|---|
| `doorReleases` | `id loggedAt imageUrl type method licensePlate { id number issuer { id name country } } accessPoint { id name } device { id name }`. `type` e.g. `VISITOR`. `method` e.g. `SWIPE_TO_OPEN`, `RFID`. |
| `calls` | `id guid loggedAt imageUrl notificationType displayStatus device { id name }`. `notificationType`: `VISITOR`, `DELIVERY`. `displayStatus`: `OPENED_DOOR`, … |
| `messages` | `... on TextMessage { id title body createdAt logoUrl(size:) imageUrl(size:) origin source { ... on Device { name } } }`. `$imageSize` is `"thumb"` or `"medium"`. |

Results come back newest first.

### 5.6 Not needed for guest access

The operations `GetBLECredentials`, `TenantRemoteLocks`, `TenantSmartLocks` and
`TenantLPRSettings` (`vehicleVisitorPassesEnabled`, …) exist but are not used
for guest access.

---

## 6. Unlock service

```
POST https://api.unlock.prod.butterflymx.com/v1/access-point
Authorization: Bearer <api token>
Content-Type: application/json

{"accessPointId": "prod-access_point-70001", "tenantId": "prod-tenant-8000001", "source": "mobile_app"}

200 {"requestId": "<uuid>"}
```

---

## 7. REST API `/v3` (JSON:API)

### 7.1 Conventions

- Base: `https://api.butterflymx.com/v3`. Responses have
  `Content-Type: application/vnd.api+json; charset=utf-8`. Requests are sent as
  `application/json`.
- Resource: `{"id": "<numeric string>", "type": "<plural snake_case>", "attributes": {...}, "relationships": {name: {"data": ref | [ref] | null}}}`.
- **Resolve `included` by the `(type, id)` pair.** Relationships are
  polymorphic: `devices` mixes `panels` and `cloud_keyz_controllers`, which
  have independent ID spaces.
- Pagination: `page[number]` (1-based) and `page[size]` (the official app uses 20).
  The response has `links { self first prev next last }`. Stop when
  `links.next` is `null`. There is no `meta`.
- Responses carry weak `ETag`s, and `If-None-Match` gets a `304`.
- Creates return `201` with the created resource. Updates and deletes return `204`
  with no body.

### 7.2 Time semantics

| Field | Wire format | Zone |
|---|---|---|
| `starts_at`, `ends_at` | RFC 3339, the official app sends **UTC `Z`** (`2026-11-12T05:00:00Z`). `-0700`-style offsets are also accepted. | absolute instant |
| `start_date`, `end_date` | `YYYY-MM-DD` | **building-local** (`Building.timeZone`) |
| `time_from`, `time_to` | `HH:MM` 24 h | **building-local** |
| `weekdays` | `["mon","tue","wed","thu","fri","sat","sun"]` | n/a |

The server **derives the other representation** whichever way the pass was
created:

- **Custom** (sent `starts_at`/`ends_at`): the server fills in `start_date`,
  `end_date`, `time_from` and `time_to` in building time. For example, sending
  `05:00Z–06:00Z` in `America/Los_Angeles` returns `start_date=end_date` = the
  local date, `time_from=21:00` and `time_to=22:00`.
- **Recurring** (sent dates, times and weekdays): the server fills in
  `starts_at = start_date@time_from` and `ends_at = end_date@time_to`, both
  converted from building time to UTC. For example, `2026-11-11` / `09:00` →
  `2026-11-11T17:00:00Z`, and `2026-11-30` / `17:00` → `2026-12-01T01:00:00Z`.

### 7.3 Keychain resource (`keychains`)

| Attribute | Type | Notes |
|---|---|---|
| `name` | string | Pass label |
| `kind` | `custom` \| `recurring` \| `delivery_pass` | |
| `starts_at`, `ends_at` | instant | Always present (see §7.2) |
| `start_date`, `end_date` | date | Always present |
| `time_from`, `time_to` | `HH:MM` | Always present. They are only meaningful as a daily window when `kind=recurring`. |
| `weekdays` | weekday[] | `[]` unless recurring |
| `allow_unit_access` | bool | The official app always sends `false`. |

| Relationship | Types |
|---|---|
| `virtual_keys` | `virtual_keys[]` |
| `devices` | `panels[]` and `cloud_keyz_controllers[]` (derived from the chosen access points) |

### 7.4 Keychain endpoints

#### List: `GET /v3/access_codes`

```
GET /v3/access_codes
  ?filter[tenant]=8000001
  &filter[status]=active                       # active | expired; any other value is ignored → all passes
  &include=devices,virtual_keys,virtual_keys.door_releases,virtual_keys.door_releases.panel
  &page[size]=20&page[number]=1
```

- `active` means **not yet ended**: it includes passes whose `starts_at` is
  still in the future.
  `expired` means `ends_at` has passed, or a delivery pass's one-time key was
  used. Any other `filter[status]` value is ignored and returns every pass.
- Results include `delivery_pass` keychains. Filter them client-side if they
  aren't wanted.
- `expired` returns newest first and paginates.

#### Get: `GET /v3/keychains/{id}?include=virtual_keys`

`data` is the keychain and `included` holds its virtual keys. Add `devices` to
`include` for device names.

#### Create custom: `POST /v3/keychains/custom` → `201`

```json
{
  "data": {
    "type": "keychains",
    "attributes": {
      "kind": "custom",
      "name": "Guest name or label",
      "starts_at": "2026-11-12T05:00:00Z",
      "ends_at":   "2026-11-12T06:00:00Z",
      "allow_unit_access": false,
      "recipients": [
        {"name": "Alex Guest", "deliver_to": "alex@example.com"}
      ],
      "start_date": null, "end_date": null, "time_from": null, "time_to": null, "weekdays": null
    },
    "relationships": {
      "tenant":        {"data": {"type": "tenants", "id": "8000001"}},
      "access_points": {"data": [{"type": "access_points", "id": "70001"}, {"type": "access_points", "id": "70002"}]},
      "virtual_keys":  {"data": []},
      "devices":       {"data": []}
    }
  }
}
```

- **`recipients` creates the virtual keys in the same request.** The `201`
  response includes them in `included`, each with its `pin`,
  `qr_code_image_url` and `instructions_url`.
- The official app sends the unused schedule fields as explicit `null`; they
  may also be omitted.
- The response also includes the derived `devices` (panels and cloud
  controllers).
- Validation errors are `400` with a JSON:API `errors` array whose members
  carry only `source.pointer` and `detail` (no `status`, `code` or `title`), one
  member per offending attribute:

  ```json
  {"errors": [
    {"source": {"pointer": "/data/attributes/starts_at"}, "detail": "Start time must be before the end time"},
    {"source": {"pointer": "/data/attributes/ends_at"},   "detail": "End time must be after the start time"}
  ]}
  ```

- Maximum length: `ends_at` "cannot exceed 365 days from start date" (`400`,
  pointer `/data/attributes/ends_at`). That equals the building's
  `virtualKeysDurationPeriod`.

#### Create recurring: `POST /v3/keychains/recurring` → `201`

```json
{
  "data": {
    "type": "keychains",
    "attributes": {
      "kind": null,
      "name": "Dog walker",
      "weekdays": ["mon", "wed", "fri"],
      "time_from": "09:00",
      "time_to": "17:00",
      "start_date": "2026-11-11",
      "end_date": "2026-11-30",
      "allow_unit_access": false,
      "recipients": [{"name": "Alex Guest", "deliver_to": "alex@example.com"}],
      "starts_at": null,
      "ends_at": null
    },
    "relationships": {
      "tenant":        {"data": {"type": "tenants", "id": "8000001"}},
      "access_points": {"data": [{"type": "access_points", "id": "70001"}]},
      "virtual_keys":  {"data": []},
      "devices":       {"data": []}
    }
  }
}
```

The response has `kind: "recurring"`, with `starts_at`/`ends_at` derived (§7.2).

#### Update custom / recurring: **does not exist**

The official app has no way to edit a guest pass after creation, and the API
has none either: `PATCH /v3/keychains/custom/{id}` and
`PATCH /v3/keychains/recurring/{id}` do not exist, and the server answers
**404** with an HTML page. Guest passes are **immutable**: to change one, create a
new pass and delete the old one. Only delivery passes can be patched (§7.4a).

#### Delete: `DELETE /v3/keychains/{id}` → `204`

This revokes the pass and all of its virtual keys.

### 7.4a Delivery passes

A delivery pass is a keychain with `kind: "delivery_pass"`. It holds **one
virtual key with no recipient** (nothing is sent). The key is a **one-time
key**: on first use, `used_at` and `one_time_key_used_at` are set and the pass
ends. Default validity is 30 days from creation.

#### Create: `POST /v3/keychains/delivery_pass` → `201`

```json
{"data": {"type": "keychains",
  "attributes": {"name": "Delivery Pass",
    "kind": null, "starts_at": null, "ends_at": null, "start_date": null, "end_date": null,
    "time_from": null, "time_to": null, "weekdays": null, "allow_unit_access": null},
  "relationships": {
    "tenant":        {"data": {"type": "tenants", "id": "8000001"}},
    "access_points": {"data": []},
    "virtual_keys":  {"data": []},
    "devices":       {"data": []}}}}
```

The response is the keychain (`kind: delivery_pass`, `starts_at` = now,
`ends_at` = now + 30 days) with `included` holding its one virtual key
(`name` = the pass name, `pin`, `qr_code_image_url`, `instructions_url`,
`email`/`sms_number` = `null`) and the devices. With `access_points` empty, the
server grants **every virtual-key-capable door**. A non-empty list is
**ignored**: delivery passes always cover all virtual-key doors.

#### Update (rename / extend): `PATCH /v3/keychains/delivery_pass/{id}` → `204` (no body)

The official app sends the **full** attribute set, as read, with its changes applied:

```json
{"data": {"type": "keychains",
  "attributes": {"kind": "delivery_pass", "name": "Amazon",
    "starts_at": "2026-11-12T05:12:03Z", "ends_at": "2027-01-10T21:12:03-0800",
    "start_date": "2026-11-11", "end_date": "2026-12-11",
    "time_from": "21:12", "time_to": "21:12", "weekdays": [], "allow_unit_access": false},
  "relationships": {
    "tenant":        {"data": {"type": "tenants", "id": null}},
    "virtual_keys":  {"data": [{"type": "virtual_keys", "id": "52000001"}]},
    "access_points": {"data": []},
    "devices":       {"data": []}}}}
```

- **Rename**: changing `name` renames both the keychain and its virtual key.
- **Extend**: the official app's "extend 30 days" sets `ends_at` to the old
  `ends_at` plus 30 days, formatted with a numeric offset (`-0800`). It does
  not update `end_date`; the server recalculates `end_date` from `ends_at`.
  So `ends_at` takes precedence.
- Re-read the pass afterwards (`GET /v3/keychains/{id}`), because the response
  has no body.

#### Delete: `DELETE /v3/keychains/{id}` → `204`

Same endpoint as the other kinds.

### 7.5 Virtual keys

#### Resource (`virtual_keys`)

| Attribute | Type | Notes |
|---|---|---|
| `name` | string | Recipient name |
| `email` | string \| null | Set when delivered by email |
| `sms_number` | string \| null | Set when delivered by SMS, normalized to E.164 (`+13155550123`) |
| `pin` | string | **6 digits**, may have leading zeros. Returned on create and on every read. |
| `qr_code_image_url` | URL | `https://s3.dualstack.us-east-1.amazonaws.com/bmx-rails-production/system/qr_keys/qr_code_images/…/original/qr_code_….png`. **Publicly readable without auth**, so anyone with the URL can display the QR. Treat it as a secret like the PIN. |
| `instructions_url` | URL | `https://user.butterflymx.com/public/virtual_keys/{id}/{hex secret}`: a public guest page |
| `sent_at` | instant \| null | `null` right after creation. Set once ButterflyMX sends the email or SMS (asynchronously, within seconds). |
| `used_at`, `one_time_key_used_at` | instant \| null | Set only on **one-time keys** (delivery passes) when they are consumed. Both are set together when the key is used. Keys of custom and recurring passes keep both `null`, so these are **not** "last used" fields. Use `door_releases` for guest-key usage. |
| `synced_with_remote_lock` | bool | |

| Relationship | Types |
|---|---|
| `door_releases` | `door_releases[]` |
| `vehicle` | `null` |

#### Add keys to an existing keychain: `POST /v3/keychains/{keychain_id}/virtual_keys` → `201`

```json
{"data": {"type": "virtual_keys", "attributes": {
  "recipients": [{"name": "Alex Guest", "deliver_to": "(315) 555-0123"}],
  "name": null, "email": null, "sms_number": null, "pin": null, "used_at": null, "qr_code_image_url": null
}}}
```

→ `data: virtual_keys[]`, one per recipient.

**The delivery channel is determined by `deliver_to`**: an email address means
email delivery, and a phone number means SMS. A loosely formatted US number
(`(315) 555-0123`) is accepted and normalized to `+13155550123`.

#### Revoke one key: `DELETE /v3/keychains/{keychain_id}/virtual_keys/{id}` → `204`

### 7.6 Door releases (`door_releases`)

Attributes: `release_method` (e.g. `virtual_key_pin`), `door_release_type`,
`panel_user_type`, `name`, `created_at`, `logged_at`, `thumb_url`,
`medium_url`, `call_guid` and `delivery_guid`. Relationships: `unit`, `user`,
`panel` and `device`.

### 7.7 Devices

- `panels`: `name`, `nfc.uuid`. Relationship: `building`.
- `cloud_keyz_controllers`: `name`. Relationship: `building`.

### 7.8 Me, integrations, calls

`GET /v3/me`, `/v3/tenants/{id}/integrations` (webhooks) and
`/v3/me/calls/{guid}/…` exist for partner tokens. The resident mobile app
uses GraphQL instead.

### 7.9 Push device registration (`/mobile/v4`)

| Method | Path | Body (form-encoded) |
|---|---|---|
| `POST` (→ `200` with body) | `/mobile/v4/users/devices` | `device[client]=iphone`, `device[client_version]`, `device[description]` (model), `device[token]`, `device[voip_token]`, `device[locales][]`, `device[development]=0` |
| `PATCH` | `/mobile/v4/users/devices/{id}` | `device[client]=iphone` (heartbeat on app foreground) |
| `DELETE` | `/mobile/v4/users/devices/{id}` | n/a (on logout) |

Response type: `user_device_apples` with `graphql_id`
`prod-user_device_apple-{id}`.

---

## 8. HTTP status semantics

| Status | Where | Meaning | Client action |
|---|---|---|---|
| `200/201/204` | all | Success | n/a |
| `302/303` | accounts | Login flow navigation | Follow manually |
| `304` | `/v3` GET with `If-None-Match` | Not modified | Use the cached body |
| `401` | API | API token invalid | Re-run the denizen login (refreshing the OAuth token first if needed), retry once |
| `422` | accounts 2FA | Wrong code | Retry with the fresh CSRF token |
| `400` | `/v3` | Validation (`errors[].source.pointer` + `detail`) | Surface the details |
| `404` | `/v3` | Unknown route or resource. Unknown routes return an **HTML** error page, not JSON. | Fail |
| `5xx` | all | Server error | Retry idempotent requests only |

---

## 9. Rate limits and terms

This is a private API that can change without notice. Use it only with your own account and doors you are authorized
to open. Decode leniently: ignore unknown fields, accept `null`, and accept
unknown enum values and ID type tags.

---

## 10. Guest-access flow (reference sequence)

```
1. Login            email + password → 2FA challenge → code
                    → OAuth tokens → denizen login → API token          (persist all)
2. Tenants          GraphQL Tenants → tenant + building.timeZone
3. Doors            GraphQL TenantAccessPoints → doors with VIRTUAL_KEYS capability (use legacyId)
4. Create pass      POST /v3/keychains/custom | /v3/keychains/recurring  with recipients[1]
                    → keychain id + virtual key {pin, qr_code_image_url, instructions_url}
                    (ButterflyMX emails or texts the guest)
5. Display          Show the PIN, QR and instructions link to the tenant
6. Monitor          GET /v3/keychains/{id}?include=virtual_keys.door_releases  (sent_at, door releases)
7. Revoke           DELETE /v3/keychains/{id}
```

Because step 4 is a single request, there is no partial-failure state to roll
back.
