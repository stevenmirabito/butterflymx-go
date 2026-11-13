# Test fixtures

Recorded, fully pseudonymized HTTP exchanges for testing the ButterflyMX
client without network access. Every value that identified a real person,
building, door, device or credential has been replaced (see
[Pseudonymization](#pseudonymization)).

## Layout

| Directory | Content |
|---|---|
| `accounts/` | Token exchange and region discovery. The recorded login and 2FA pages were removed when ButterflyMX replaced its accounts app (November 2026); the login flow is described in `API_SPEC.md` §3 and emulated by `butterflymxtest`. |
| `denizen/` | `POST /denizen/v1/login` (OAuth token to API token) and `DELETE /denizen/v1/logout`. |
| `graphql/` | One file per GraphQL operation, named after `operationName`. `TenantDoorReleases` and `TenantCalls` have `hasNextPage: true`. |
| `rest/` | `/v3` access code lists (active in several states, expired, `304`), keychain gets, creates (custom, recurring, delivery pass, extra virtual key), delivery-pass `PATCH`es, deletes, and `/mobile/v4/users/devices`. |
| `unlock/` | The unlock service request. |

File names are `<method>-<resource>-<status>[-<state>].json`. The `<state>`
suffix tells apart responses to the same request at different points of the
session (for example `after-custom-create`, `after-delivery-pass-extend`).

## File format

One exchange per file, always valid JSON:

```json
{
  "request": {
    "method": "POST",
    "path": "/v3/keychains/custom",
    "query": {"key": "value"},
    "headers": {"content-type": "...", "accept": "...", "user-agent": "..."},
    "body": null
  },
  "response": {
    "status": 201,
    "headers": {"content-type": "...", "etag": "..."},
    "body": null
  }
}
```

- `query` holds the decoded query-string parameters (repeated keys become
  arrays).
- `headers` are lower-cased and limited to `content-type`, `accept`,
  `location`, `etag`, `if-none-match`, `x-bmx-service` and `user-agent`.
  `Authorization`, cookies and CSRF headers are never included.
- `body` is the decoded JSON value, a string, or `null` when there is no body.
  Form-encoded request bodies become JSON objects of the remaining fields.
  Repeated `key[]` fields become arrays.
- The secret form fields `login[password]`, the 2FA `code` and
  `authenticity_token` were dropped from the request bodies, so they are
  absent rather than faked.
- HTML bodies are strings, trimmed to what a parser needs: scripts, styles,
  links, SVG, iframes, nonces, classes and `data-*` attributes are removed.
  The `csrf-param` and `csrf-token` meta tags, every `<form>` with its inputs,
  headings, error messages and links are kept. Turbo-stream bodies are kept
  verbatim apart from redacted values.
- Timestamps and dates are unchanged.

## Pseudonymization

One mapping is applied consistently across all files, so references stay
intact (the same real value always becomes the same fake value).

| Kind | Replacement |
|---|---|
| Numeric IDs (REST `id`, `legacyId`, numbers inside global IDs such as `prod-tenant-N`, IDs in paths, query strings, `links` and cursors) | Random number with the same number of digits. |
| Resident | `Resident Example`, `resident@example.com`, `+15555550100`. National forms become `5555550100` and `(555) 555-0100`. |
| Guests | `Guest One`, `Guest Two`, ... with `+155555501NN` and `guestN@example.com`. Pass labels that named a person become `Guest Pass One`, ... |
| Building, unit | `Example Tower`, unit `4B` (floor `4`), building `guid` `prod-core-na-building-<id>`. |
| Door, access point and device names | `Main Entrance`, `Front Door`, `Side Door`, `Garage Gate`, `Bike Room`, `Stairwell Door`, and combined names such as `Front Door & Stairwell Door`. |
| PINs (`pin`, `pinCode`) | Distinct fake 6-digit strings, some with a leading zero (for example `012345`). |
| Tokens | `FAKE_ACCESS_TOKEN`, `FAKE_REFRESH_TOKEN`, `FAKE_ID_TOKEN`, `FAKE_API_TOKEN`, `FAKE_PUSH_TOKEN`, `FAKE_VOIP_TOKEN`. CSRF tokens are random base64url strings. |
| URLs | Avatar `https://example.com/avatar.jpg`. Door-release and call images `https://example.com/images/<n>.jpg` (the `no_image` CDN placeholder is unchanged). `instructions_url` and `qr_code_image_url` keep their shape with fake IDs and suffixes. |
| BLE credentials, serial numbers | Random hex or alphanumeric strings of the same length and shape. |
| UUIDs (call `guid`, unlock `requestId`) | Random UUIDs. |
| `ETag` values | Random hex of the same length. A `304` fixture's `if-none-match` matches the `etag` of the response it revalidates. |
| GraphQL `endCursor` | Re-encoded with fake values. The door-release cursor is base64 JSON (`occurredAt`, `id`) with a fake `id`. |

Left as is: all timestamps and dates, the public OAuth `client_id`, the
building time zone (`America/Los_Angeles`), the push-device model string, app
and OS versions, and generic labels ("Delivery Pass", "Test", ...).

### PKCE values

The OAuth `code` and `code_verifier` in `accounts/post-oauth-token-200.json`
are fake but valid-shaped (43-character base64url). The conformance test
signs in with `base64url(sha256(code_verifier))` as the challenge, so the
recorded exchange can be replayed against the fake.

## Adding fixtures

Never commit raw captures. Any new exchange must go through the same
pseudonymization and be checked against a list of the real values before it is
added.
