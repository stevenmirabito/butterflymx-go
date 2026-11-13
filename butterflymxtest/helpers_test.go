package butterflymxtest

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// fixedNow is the instant of the delivery pass creation in the capture.
var fixedNow = time.Date(2026, 11, 12, 5, 12, 3, 0, time.UTC)

func newTestServer(t *testing.T, opts ...Option) *Server {
	t.Helper()
	s := NewServer(opts...)
	t.Cleanup(s.Close)
	return s
}

// newClient is a plain net/http client with a cookie jar that never follows
// redirects, like the app's login flow.
func newClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type reply struct {
	*http.Response
	Body []byte
}

func (r reply) JSON(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("response is not a JSON object (status %d): %v\n%s", r.StatusCode, err, r.Body)
	}
	return m
}

func do(t *testing.T, c *http.Client, method, u string, body []byte, hdr map[string]string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, u, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return reply{resp, b}
}

func wantStatus(t *testing.T, r reply, want int) {
	t.Helper()
	if r.StatusCode != want {
		t.Fatalf("status = %d, want %d\nbody: %s", r.StatusCode, want, r.Body)
	}
}

var reToken = regexp.MustCompile(`name="_csrf_token" value="([^"]+)"`)

// csrfToken is the page's _csrf_token (every form carries the same one).
func csrfToken(t *testing.T, body []byte) string {
	t.Helper()
	m := reToken.FindSubmatch(body)
	if m == nil {
		t.Fatalf("page has no csrf token:\n%s", body)
	}
	return string(m[1])
}

var reHref = regexp.MustCompile(`href="([^"]*)"`)

// appCallback parses the "Returning to app" page's link to the app.
func appCallback(t *testing.T, r reply) *url.URL {
	t.Helper()
	wantStatus(t, r, 200)
	for _, m := range reHref.FindAllSubmatch(r.Body, -1) {
		if l := html.UnescapeString(string(m[1])); strings.HasPrefix(l, RedirectURI) {
			u, err := url.Parse(l)
			if err != nil {
				t.Fatal(err)
			}
			return u
		}
	}
	t.Fatalf("no link to the app:\n%s", r.Body)
	return nil
}

type pkce struct{ verifier, challenge string }

func newPKCE() pkce {
	v := randToken(32)
	sum := sha256.Sum256([]byte(v))
	return pkce{v, base64.RawURLEncoding.EncodeToString(sum[:])}
}

func authorizeURL(base string, p pkce, state string, prompt bool) string {
	q := url.Values{
		"client_id": {ClientID}, "redirect_uri": {RedirectURI}, "response_type": {"code"}, "scope": {"openid profile"},
		"code_challenge": {p.challenge}, "code_challenge_method": {"S256"}, "nonce": {"n0nce"}, "state": {state},
	}
	if prompt {
		q.Set("prompt", "login")
	}
	return base + "/oauth/authorize?" + q.Encode()
}

func formBody(kv ...string) []byte {
	v := url.Values{}
	for i := 0; i < len(kv); i += 2 {
		v.Add(kv[i], kv[i+1])
	}
	return []byte(v.Encode())
}

// formHdr is a browser's plain form post: no CSRF header, the token travels
// in the body (and the _csrf_token cookie the client's jar holds).
func formHdr() map[string]string {
	return map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Accept":       "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	}
}

// loginBody is the login form's post body.
func loginBody(tok, email, password string) []byte {
	return formBody("_csrf_token", tok, "return_to", "/oauth/authorize", "email", email, "password", password, "commit", "Sign in with email")
}

type tokens struct {
	Access, Refresh, API string
	Raw                  map[string]any
}

// login drives the whole flow exactly as the app does and returns the tokens.
func login(t *testing.T, s *Server) tokens { t.Helper(); return loginClient(t, s, newClient()) }

func loginClient(t *testing.T, s *Server, c *http.Client) tokens {
	t.Helper()
	p := newPKCE()
	code := authorizeCode(t, s, c, p, randToken(16))
	r := do(t, c, "POST", s.URL()+"/oauth/token", formBody(
		"grant_type", "authorization_code", "code", code, "code_verifier", p.verifier,
		"redirect_uri", RedirectURI, "client_id", ClientID), map[string]string{"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})
	wantStatus(t, r, 200)
	raw := r.JSON(t)
	tk := tokens{Access: raw["access_token"].(string), Refresh: raw["refresh_token"].(string), Raw: raw}
	tk.API = denizenLogin(t, s, tk.Access)
	return tk
}

// authorizeCode drives the sign-in as the app does (authorize, login page,
// password, TOTP when 2FA is on, the "Returning to app" page) and returns the
// authorization code from the link to the app.
func authorizeCode(t *testing.T, s *Server, c *http.Client, p pkce, state string) string {
	t.Helper()
	r := do(t, c, "GET", authorizeURL(s.URL(), p, state, true), nil, nil)
	wantStatus(t, r, 302)
	if !strings.HasSuffix(r.Header.Get("Location"), "/login/new") {
		t.Fatalf("authorize location = %q", r.Header.Get("Location"))
	}
	r = do(t, c, "GET", s.URL()+"/login/new", nil, nil)
	wantStatus(t, r, 200)
	r = do(t, c, "POST", s.URL()+"/login", loginBody(csrfToken(t, r.Body), DefaultEmail, DefaultPassword), formHdr())
	wantStatus(t, r, 302)

	loc := r.Header.Get("Location")
	if s.cfg.mfa {
		if !strings.Contains(loc, "/login/two_factor_authentication/new?type=authenticator_app") {
			t.Fatalf("2FA location = %q", loc)
		}
		r = do(t, c, "GET", s.URL()+loc, nil, nil)
		wantStatus(t, r, 200)
		r = do(t, c, "POST", s.URL()+"/login/two_factor_authentication",
			formBody("_csrf_token", csrfToken(t, r.Body), "type", "authenticator_app", "code", s.CurrentTOTP()), formHdr())
		wantStatus(t, r, 302)
		loc = r.Header.Get("Location")
	}
	if !strings.HasPrefix(loc, "/oauth/authorize?") {
		t.Fatalf("post-login location = %q", loc)
	}
	cb := appCallback(t, do(t, c, "GET", s.URL()+loc, nil, nil))
	if cb.Query().Get("state") != state {
		t.Fatalf("callback = %q", cb)
	}
	return cb.Query().Get("code")
}

func denizenLogin(t *testing.T, s *Server, oauth string) string {
	t.Helper()
	body := `{"access_token":"` + oauth + `","device":{"platform":"ios","version":"1001.125.2","locales":["en-US"]}}`
	r := do(t, newClient(), "POST", s.URL()+"/denizen/v1/login", []byte(body), map[string]string{"Content-Type": "application/json"})
	wantStatus(t, r, 200)
	return r.JSON(t)["token"].(string)
}

// api sends a JSON request with the API token.
func api(t *testing.T, s *Server, tok, method, path string, body any) reply {
	t.Helper()
	var b []byte
	if body != nil {
		switch v := body.(type) {
		case string:
			b = []byte(v)
		case []byte:
			b = v
		default:
			var err error
			if b, err = json.Marshal(v); err != nil {
				t.Fatal(err)
			}
		}
	}
	h := map[string]string{"Authorization": "Bearer " + tok, "Accept": "*/*"}
	if b != nil {
		h["Content-Type"] = "application/json"
	}
	return do(t, newClient(), method, s.URL()+path, b, h)
}

// dig walks a decoded JSON value by keys and indexes.
func dig(t *testing.T, v any, path ...any) any {
	t.Helper()
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				t.Fatalf("dig %v: not an object at %q (%T)", path, k, v)
			}
			v = m[k]
		case int:
			a, ok := v.([]any)
			if !ok || k >= len(a) {
				t.Fatalf("dig %v: bad index %d", path, k)
			}
			v = a[k]
		}
	}
	return v
}

// ---- fixtures ---------------------------------------------------------------

type fixture struct {
	Name    string
	Request struct {
		Method  string            `json:"method"`
		Path    string            `json:"path"`
		Query   map[string]any    `json:"query"`
		Headers map[string]string `json:"headers"`
		Body    jsontext.Value    `json:"body"`
	} `json:"request"`
	Response struct {
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    jsontext.Value    `json:"body"`
	} `json:"response"`
}

func loadFixture(t testing.TB, rel string) fixture {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", rel+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	f.Name = rel
	return f
}

// rawBody returns the fixture request body as the JSON text, or "" for null.
func (f fixture) reqJSON() string {
	if string(f.Request.Body) == "null" || len(f.Request.Body) == 0 {
		return ""
	}
	return string(f.Request.Body)
}

func (f fixture) queryString() string {
	v := url.Values{}
	for k, x := range f.Request.Query {
		switch t := x.(type) {
		case string:
			v.Add(k, t)
		case []any:
			for _, e := range t {
				v.Add(k, e.(string))
			}
		}
	}
	return v.Encode()
}

// formFromFixture turns a decoded form-encoded fixture body into a form body.
func formFromFixture(t testing.TB, body string) url.Values {
	t.Helper()
	m := map[string]any{}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	v := url.Values{}
	for k, x := range m {
		switch t := x.(type) {
		case string:
			v.Add(k, t)
		case []any:
			for _, e := range t {
				v.Add(k, e.(string))
			}
		}
	}
	return v
}

// replaceIDs substitutes fixture IDs by the IDs of the fake world.
func replaceIDs(s string, ids map[string]string) string {
	var pairs []string
	for k, v := range ids {
		pairs = append(pairs, k, v)
	}
	return strings.NewReplacer(pairs...).Replace(s)
}

// gql posts a GraphQL operation as the app does.
func gql(t *testing.T, s *Server, tok, op string, vars map[string]any) reply {
	t.Helper()
	b, _ := json.Marshal(map[string]any{
		"operationName": op, "query": "query " + op + " { __typename }", "variables": vars,
		"extensions": map[string]any{"clientLibrary": map[string]any{"name": "apollo-ios", "version": "2.4.0"}},
	})
	return do(t, newClient(), "POST", s.URL()+"/denizen/v1/graphql", b, map[string]string{
		"Authorization": "Bearer " + tok, "Content-Type": "application/json", "x-bmx-service": "denizen-api",
		"Accept": "multipart/mixed;deferSpec=20220824,application/graphql-response+json,application/json",
	})
}

// apiSession logs in and returns the API token.
func apiSession(t *testing.T, s *Server) string { t.Helper(); return login(t, s).API }
