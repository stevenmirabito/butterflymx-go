// Package butterflymxtest is a public, stateful, in-memory fake of
// ButterflyMX, built on net/http/httptest.
//
// It speaks the wire protocol described in API_SPEC.md: the accounts host
// (OAuth, login form, TOTP, SMS and email 2FA, token exchange, region discovery), the main
// API host (denizen login/logout, GraphQL, REST /v3 JSON:API, /mobile/v4) and
// the unlock service. One [Server] serves the paths of all three hosts, so
// the accounts, API and unlock base URLs are all [Server.URL].
//
// The fake imports neither the butterflymx client package nor its auth
// package; it only knows the wire format, which makes it an independent check
// of the client. It is intended for the library's own tests and for the
// integration tests of applications that use the library.
//
// The server uses plain HTTP, not TLS: that keeps cookie handling and
// transports simple, and nothing in the fake is security-sensitive. Real
// ButterflyMX hosts are HTTPS only, so a client that insists on HTTPS must be
// configured to allow plain HTTP for the fake's URL.
//
// Everything is seeded with a small pseudonymized world that mirrors
// testdata/: a resident, a tenant in unit 4B of "Example Tower", seven doors
// (six of them guest-pass capable), a few existing guest passes, expired
// passes, door releases, calls and messages. See [Seed].
//
// GraphQL responses carry the fields the official app selects (the fixture
// shapes), not only the fields a given query selects: clients must decode
// leniently, as the spec requires anyway.
package butterflymxtest

import (
	"bytes"
	"crypto/md5" //nolint:gosec // ETags only.
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	_ "time/tzdata" // the building time zone must resolve on any machine
)

// Seeded credentials of the resident account.
const (
	// DefaultEmail is the email address of the seeded resident.
	DefaultEmail = "resident@example.com"
	// DefaultPassword is the password of the seeded resident.
	DefaultPassword = "correct horse battery staple"
)

const (
	// ClientID is the public OAuth client id the fake accepts (the iOS app's).
	ClientID = "0e3aeeb7cec2782b9fb21352a4349a44405ed5d7674072416b6481d51abfd6b6"
	// RedirectURI is the OAuth redirect URI the fake accepts.
	RedirectURI = "com.butterflymx.oauth://oauth"
)

type config struct {
	clock    func() time.Time
	mfa      bool
	lastMFA  string
	mfaGET   bool
	mfaLand  bool // login lands on the method picker
	tokenTTL time.Duration
	apiTTL   time.Duration
	pageSize int
}

// Option configures a [Server].
type Option func(*config)

// WithClock makes the server read the current time from f instead of
// time.Now. The clock drives token expiry, TOTP windows, pass status, "now"
// for new delivery passes and the seeded data (which is generated relative to
// the clock at construction).
func WithClock(f func() time.Time) Option { return func(c *config) { c.clock = f } }

// WithoutMFA makes accounts with the seeded credentials log in without a
// second factor: POST /login redirects straight back to the authorize
// endpoint.
func WithoutMFA() Option { return func(c *config) { c.mfa = false } }

// WithTokenTTL sets the lifetime of OAuth access tokens (default 24 h, the
// expires_in the real server returns).
func WithTokenTTL(d time.Duration) Option { return func(c *config) { c.tokenTTL = d } }

// WithAPITokenTTL makes denizen API tokens expire d after issue (default: they
// never expire). Expired tokens get 401.
func WithAPITokenTTL(d time.Duration) Option { return func(c *config) { c.apiTTL = d } }

// WithPageSize sets the default page size of GraphQL connections and of
// /v3/access_codes when the request does not say (default 20).
func WithPageSize(n int) Option { return func(c *config) { c.pageSize = n } }

// RecordedRequest is one request seen by the server, with secrets redacted.
type RecordedRequest struct {
	Time   time.Time
	Method string
	Path   string
	Query  url.Values
	// Header holds Content-Type, Accept, If-None-Match, User-Agent,
	// X-Bmx-Service and X-Csrf-Token; Authorization is present as
	// "Bearer [REDACTED]" when the request carried a bearer token.
	Header http.Header
	// Body is the request body with token, password and code values replaced
	// by "[REDACTED]".
	Body string
	// Status is the response status the server sent.
	Status int
	// Faulted is true when the response came from [Server.FailNext].
	Faulted bool
}

type fault struct {
	method, prefix string
	status         int
	n              int
}

// Server is the fake ButterflyMX. It is safe for concurrent use.
type Server struct {
	cfg config
	ts  *httptest.Server
	mux *http.ServeMux

	mu  sync.Mutex
	rnd *mrand.Rand

	totpSecret string
	lastMFA    string // last successfully used 2FA method of the resident
	deliveries []MFADelivery

	sessions      map[string]*session
	codes         map[string]*authCode
	accessTokens  map[string]*accessToken
	refreshTokens map[string]*refreshToken
	apiTokens     map[string]*apiToken

	w *world

	faults   []*fault
	requests []RecordedRequest
}

// NewServer starts a fake server. Call [Server.Close] when done.
func NewServer(opts ...Option) *Server {
	cfg := config{
		clock:    time.Now,
		mfa:      true,
		lastMFA:  mfaAuthenticator,
		mfaGET:   true,
		tokenTTL: 24 * time.Hour,
		pageSize: 20,
	}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.pageSize <= 0 {
		cfg.pageSize = 20
	}
	s := &Server{
		cfg:           cfg,
		rnd:           mrand.New(mrand.NewPCG(0xB077E2F1, 0x4D58)),
		totpSecret:    newTOTPSecret(),
		lastMFA:       cfg.lastMFA,
		sessions:      map[string]*session{},
		codes:         map[string]*authCode{},
		accessTokens:  map[string]*accessToken{},
		refreshTokens: map[string]*refreshToken{},
		apiTokens:     map[string]*apiToken{},
	}
	s.w = s.seedWorld()
	s.mux = s.routes()
	s.ts = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Close shuts the server down.
func (s *Server) Close() { s.ts.Close() }

// URL is the base URL (plain HTTP) to use as accounts, API and unlock URL.
func (s *Server) URL() string { return s.ts.URL }

// Client returns a new HTTP client for the server with its own cookie jar. It
// does not follow redirects, because the login flow is driven by hand (the
// final redirect goes to a custom URL scheme).
func (s *Server) Client() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// TOTPSecret returns the base32 secret of the seeded resident's authenticator
// app (RFC 6238, SHA1, 30 s, 6 digits).
func (s *Server) TOTPSecret() string { return s.totpSecret }

// CurrentTOTP returns the valid code for the current window of the server
// clock.
func (s *Server) CurrentTOTP() string {
	return totpCode(s.totpSecret, s.now().Unix()/30)
}

// FailNext makes the next n requests whose method equals method (empty or "*"
// matches any) and whose path starts with pathPrefix fail with status and a
// plausible body, before authentication is checked. Faults are consumed in
// the order they were added.
func (s *Server) FailNext(method, pathPrefix string, status int, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = append(s.faults, &fault{method: strings.ToUpper(method), prefix: pathPrefix, status: status, n: n})
}

// Requests returns a copy of every request the server has seen, oldest first.
func (s *Server) Requests() []RecordedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]RecordedRequest(nil), s.requests...)
}

// RevokeAPITokens invalidates every denizen API token, so that the next API
// call gets 401.
func (s *Server) RevokeAPITokens() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.apiTokens {
		t.revoked = true
	}
}

// RevokeRefreshTokens invalidates every OAuth refresh token, so that the next
// refresh gets 400 invalid_grant.
func (s *Server) RevokeRefreshTokens() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.refreshTokens {
		t.revoked = true
	}
}

// IssueAPIToken mints a valid denizen API token for the default resident
// without going through the login flow, for tests that only exercise API
// calls. The token expires after the [WithAPITokenTTL] lifetime, if one was
// set, and is invalidated by [Server.RevokeAPITokens] like any other. No
// request is recorded.
func (s *Server) IssueAPIToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mintAPIToken()
}

// IssueOAuthToken mints an OAuth access/refresh token pair for the default
// resident without going through the login flow. The access token expires at
// expiry, [WithTokenTTL] after the server clock's current time. The refresh
// token is subject to rotation and to [Server.RevokeRefreshTokens] like one
// from the real flow. No request is recorded.
func (s *Server) IssueOAuthToken() (access, refresh string, expiry time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.issueTokens(s.ts.URL, "")
	return out["access_token"].(string), out["refresh_token"].(string), s.now().Add(s.cfg.tokenTTL)
}

func (s *Server) now() time.Time { return s.cfg.clock().UTC().Truncate(time.Second) }

// ---- request pipeline ------------------------------------------------------

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	r.Body = io.NopCloser(bytes.NewReader(body))

	s.mu.Lock()
	defer s.mu.Unlock()

	sw := &statusWriter{ResponseWriter: w}
	faulted := false
	if f := s.matchFault(r); f != nil {
		faulted = true
		s.writeFault(sw, r, f.status)
	} else {
		s.mux.ServeHTTP(sw, r)
	}
	s.requests = append(s.requests, RecordedRequest{
		Time:    s.now(),
		Method:  r.Method,
		Path:    r.URL.Path,
		Query:   r.URL.Query(),
		Header:  recordHeaders(r),
		Body:    redactBody(r.Header.Get("Content-Type"), body),
		Status:  sw.status,
		Faulted: faulted,
	})
}

func (s *Server) matchFault(r *http.Request) *fault {
	for i, f := range s.faults {
		if f.n <= 0 {
			continue
		}
		if f.method != "" && f.method != "*" && f.method != r.Method {
			continue
		}
		if !strings.HasPrefix(r.URL.Path, f.prefix) {
			continue
		}
		f.n--
		if f.n == 0 {
			s.faults = append(s.faults[:i:i], s.faults[i+1:]...)
		}
		return f
	}
	return nil
}

func (s *Server) writeFault(w http.ResponseWriter, r *http.Request, status int) {
	title := http.StatusText(status)
	if title == "" {
		title = "Error"
	}
	switch status {
	case http.StatusTooManyRequests:
		w.Header().Set("Retry-After", "1")
	case http.StatusUnauthorized:
		w.Header().Set("WWW-Authenticate", `Bearer realm="ButterflyMX", error="invalid_token"`)
	}
	if strings.HasPrefix(r.URL.Path, "/v3/") || strings.HasPrefix(r.URL.Path, "/mobile/") {
		writeJSON(w, status, "application/vnd.api+json; charset=utf-8", map[string]any{
			"errors": []any{map[string]any{"status": fmt.Sprint(status), "title": title}},
		})
		return
	}
	writeJSON(w, status, "application/json; charset=utf-8", map[string]any{
		"error": strings.ToLower(strings.ReplaceAll(title, " ", "_")), "error_description": title,
	})
}

func recordHeaders(r *http.Request) http.Header {
	h := http.Header{}
	for _, k := range []string{"Content-Type", "Accept", "If-None-Match", "User-Agent", "X-Bmx-Service", "X-Csrf-Token"} {
		if v := r.Header.Values(k); len(v) > 0 {
			h[k] = append([]string(nil), v...)
		}
	}
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		h.Set("Authorization", "Bearer [REDACTED]")
	}
	if v := h.Get("X-Csrf-Token"); v != "" {
		h.Set("X-Csrf-Token", "[REDACTED]")
	}
	return h
}

var (
	secretFormKeys = map[string]bool{
		"login[password]": true, "password": true, "code": true, "authenticity_token": true, "_csrf_token": true, "code_verifier": true,
		"refresh_token": true, "device[token]": true, "device[voip_token]": true,
	}
	secretJSONKeys = map[string]bool{
		"access_token": true, "refresh_token": true, "token": true, "voip_token": true, "password": true,
	}
)

func redactBody(contentType string, body []byte) string {
	if len(body) == 0 {
		return ""
	}
	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			return "[unparseable]"
		}
		for k := range vals {
			if secretFormKeys[k] {
				vals.Set(k, "[REDACTED]")
			}
		}
		return vals.Encode()
	}
	var v any
	if json.Unmarshal(body, &v) != nil {
		return string(body)
	}
	redactJSON(v)
	out, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		return string(body)
	}
	return string(out)
}

func redactJSON(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if _, isStr := x.(string); isStr && secretJSONKeys[k] {
				t[k] = "[REDACTED]"
				continue
			}
			redactJSON(x)
		}
	case []any:
		for _, x := range t {
			redactJSON(x)
		}
	}
}

// ---- routing ---------------------------------------------------------------

func (s *Server) routes() *http.ServeMux {
	m := http.NewServeMux()
	// accounts
	m.HandleFunc("GET /oauth/authorize", s.hAuthorize)
	m.HandleFunc("GET /login/new", s.hLoginNew)
	m.HandleFunc("POST /login", s.hLogin)
	m.HandleFunc("GET "+mfaNewPath, s.hTwoFactorNew)
	m.HandleFunc("POST "+mfaNewPath, s.hTwoFactorResend)
	m.HandleFunc("GET "+mfaVerifyPath, s.hTwoFactorPicker)
	m.HandleFunc("POST "+mfaVerifyPath, s.hTwoFactor)
	m.HandleFunc("POST /oauth/token", s.hToken)
	m.HandleFunc("GET /api/mobile/regions", s.hRegions)
	// denizen
	m.HandleFunc("POST /denizen/v1/login", s.hDenizenLogin)
	m.HandleFunc("DELETE /denizen/v1/logout", s.apiAuth(s.hDenizenLogout))
	m.HandleFunc("POST /denizen/v1/graphql", s.apiAuth(s.hGraphQL))
	// REST v3
	m.HandleFunc("GET /v3/access_codes", s.apiAuth(s.hAccessCodes))
	m.HandleFunc("GET /v3/keychains/{id}", s.apiAuth(s.hGetKeychain))
	m.HandleFunc("POST /v3/keychains/custom", s.apiAuth(s.hCreateKeychain("custom")))
	m.HandleFunc("POST /v3/keychains/recurring", s.apiAuth(s.hCreateKeychain("recurring")))
	m.HandleFunc("POST /v3/keychains/delivery_pass", s.apiAuth(s.hCreateKeychain("delivery_pass")))
	m.HandleFunc("PATCH /v3/keychains/delivery_pass/{id}", s.apiAuth(s.hPatchKeychain("delivery_pass")))
	m.HandleFunc("POST /v3/keychains/{id}/virtual_keys", s.apiAuth(s.hAddVirtualKeys))
	m.HandleFunc("DELETE /v3/keychains/{id}", s.apiAuth(s.hDeleteKeychain))
	m.HandleFunc("DELETE /v3/keychains/{id}/virtual_keys/{vk}", s.apiAuth(s.hDeleteVirtualKey))
	// mobile v4
	m.HandleFunc("POST /mobile/v4/users/devices", s.apiAuth(s.hPushDevice))
	m.HandleFunc("PATCH /mobile/v4/users/devices/{id}", s.apiAuth(s.hPushDevice))
	m.HandleFunc("DELETE /mobile/v4/users/devices/{id}", s.apiAuth(s.hPushDeviceDelete))
	// unlock service
	m.HandleFunc("POST /v1/access-point", s.apiAuth(s.hUnlock))
	m.HandleFunc("/", s.hNotFound)
	return m
}

func (s *Server) hNotFound(w http.ResponseWriter, r *http.Request) {
	// Unknown /v3 routes (including PATCH on custom/recurring passes, which do
	// not exist) answer ButterflyMX's HTML error page.
	if strings.HasPrefix(r.URL.Path, "/v3/") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(notFoundHTML))
		return
	}
	if strings.HasPrefix(r.URL.Path, "/mobile/") {
		writeJSONAPIErrors(w, http.StatusNotFound, apiErr{Title: "Not Found", Detail: "no such endpoint"})
		return
	}
	writeJSON(w, http.StatusNotFound, "application/json; charset=utf-8", map[string]any{"error": "not_found"})
}

// ---- response helpers --------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, contentType string, v any) []byte {
	b, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}
	if status == http.StatusOK { // Rails adds a weak ETag to every 200
		w.Header().Set("ETag", weakETag(b))
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_, _ = w.Write(b)
	return b
}

func weakETag(b []byte) string {
	sum := md5.Sum(b) //nolint:gosec // not a security use.
	return `W/"` + hex.EncodeToString(sum[:]) + `"`
}

// writeCached writes a 200 JSON response with a weak ETag derived from the
// body, answering 304 when If-None-Match matches.
func writeCached(w http.ResponseWriter, r *http.Request, contentType string, v any) {
	b, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tag := weakETag(b)
	w.Header().Set("ETag", tag)
	if etagMatches(r.Header.Get("If-None-Match"), tag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func etagMatches(header, tag string) bool {
	if header == "" {
		return false
	}
	norm := func(t string) string { return strings.TrimPrefix(strings.TrimSpace(t), "W/") }
	for _, c := range strings.Split(header, ",") {
		if strings.TrimSpace(c) == "*" || norm(c) == norm(tag) {
			return true
		}
	}
	return false
}

const jsonAPIType = "application/vnd.api+json; charset=utf-8"

const notFoundHTML = `<!DOCTYPE html>
<html>
<head><title>The page you were looking for doesn't exist (404)</title></head>
<body><h1>The page you were looking for doesn't exist.</h1></body>
</html>
`

// writeValidation writes a /v3 validation failure as the real server does:
// HTTP 400 with members that carry only
// source.pointer and detail.
func writeValidation(w http.ResponseWriter, errs ...apiErr) {
	out := make([]any, 0, len(errs))
	for _, e := range errs {
		o := map[string]any{"detail": e.Detail}
		if e.Pointer != "" {
			o["source"] = map[string]any{"pointer": e.Pointer}
		}
		out = append(out, o)
	}
	writeJSON(w, http.StatusBadRequest, jsonAPIType, map[string]any{"errors": out})
}

// apiErr is one JSON:API error object. Other than validation failures (see
// writeValidation), the real error bodies are unverified; the fake uses the
// standard JSON:API shape.
type apiErr struct {
	Title   string
	Detail  string
	Pointer string
	Code    string
}

func writeJSONAPIErrors(w http.ResponseWriter, status int, errs ...apiErr) {
	out := make([]any, 0, len(errs))
	for _, e := range errs {
		o := map[string]any{"status": fmt.Sprint(status), "title": e.Title}
		if e.Detail != "" {
			o["detail"] = e.Detail
		}
		if e.Code != "" {
			o["code"] = e.Code
		}
		if e.Pointer != "" {
			o["source"] = map[string]any{"pointer": e.Pointer}
		}
		out = append(out, o)
	}
	writeJSON(w, status, jsonAPIType, map[string]any{"errors": out})
}

// ---- random helpers ----------------------------------------------------------

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// randID returns a pseudo-random numeric string of the given digit count that
// is not in used, and records it there. Deterministic per server.
func (s *Server) randID(digits int, used map[string]bool) string {
	lo := 1
	for i := 1; i < digits; i++ {
		lo *= 10
	}
	for {
		id := fmt.Sprint(lo + s.rnd.IntN(lo*9))
		if !used[id] {
			used[id] = true
			return id
		}
	}
}

// parseGlobalID splits "prod-access_point-70001" into ("access_point", "70001").
func parseGlobalID(id string) (typ, num string, ok bool) {
	i := strings.Index(id, "-")
	j := strings.LastIndex(id, "-")
	if i < 0 || j <= i || j == len(id)-1 {
		return "", "", false
	}
	return id[i+1 : j], id[j+1:], true
}
