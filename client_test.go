package butterflymx

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fixtureBody returns response.body of a testdata fixture.
func fixtureBody(t testing.TB, rel string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", rel))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Response struct {
			Body jsontext.Value `json:"body"`
		} `json:"response"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f.Response.Body
}

// recordingAuth is a TokenProvider that hands out tok-1, tok-2, ...
type recordingAuth struct {
	mu          sync.Mutex
	n           int
	invalidated []string
}

func (a *recordingAuth) APIToken(context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.n == 0 {
		a.n = 1
	}
	return "tok-" + string(rune('0'+a.n)), nil
}

func (a *recordingAuth) InvalidateAPIToken(_ context.Context, tok string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.invalidated = append(a.invalidated, tok)
	a.n++
	return nil
}

// newTestClient returns a Client whose Environment points at srv. The sleep
// hook records delays instead of waiting.
func newTestClient(t testing.TB, srv *httptest.Server, mod func(*Options)) (*Client, *[]time.Duration) {
	t.Helper()
	opts := Options{
		Environment: Environment{Name: "test", AccountsURL: srv.URL, APIURL: srv.URL, UnlockURL: srv.URL},
		Auth:        StaticAPIToken("tok"),
		HTTPClient:  srv.Client(),
		Retry:       RetryPolicy{MaxAttempts: 4, BaseDelay: time.Microsecond, MaxDelay: time.Millisecond},
	}
	if mod != nil {
		mod(&opts)
	}
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	var delays []time.Duration
	c.sleep = func(ctx context.Context, d time.Duration) error {
		delays = append(delays, d)
		return ctx.Err()
	}
	return c, &delays
}

func newTLS(t testing.TB, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Error("missing Auth should fail")
	}
	if _, err := New(Options{Auth: StaticAPIToken("x"), Environment: Environment{Name: "bad", AccountsURL: "http://x", APIURL: "http://y"}}); err == nil {
		t.Error("invalid environment should fail")
	}
	c, err := New(Options{Auth: StaticAPIToken("x")})
	if err != nil {
		t.Fatal(err)
	}
	if c.Environment() != Production {
		t.Errorf("default environment = %v", c.Environment().Name)
	}
	if c.retry != (RetryPolicy{MaxAttempts: 4, BaseDelay: 250 * time.Millisecond, MaxDelay: 5 * time.Second}) {
		t.Errorf("default retry = %+v", c.retry)
	}
	if c.ua != DefaultUserAgent {
		t.Errorf("ua = %q", c.ua)
	}
}

func TestStaticAPIToken(t *testing.T) {
	var p TokenProvider = StaticAPIToken("abc")
	tok, err := p.APIToken(t.Context())
	if err != nil || tok != "abc" {
		t.Fatalf("got %q, %v", tok, err)
	}
	if err := p.InvalidateAPIToken(t.Context(), "abc"); err != nil {
		t.Fatal(err)
	}
	if tok, _ := p.APIToken(t.Context()); tok != "abc" {
		t.Errorf("token changed to %q", tok)
	}
}

func TestBackoffBounds(t *testing.T) {
	c, _ := New(Options{Auth: StaticAPIToken("x"), Retry: RetryPolicy{BaseDelay: 10 * time.Millisecond, MaxDelay: 40 * time.Millisecond}})
	for n := 1; n <= 6; n++ {
		for range 50 {
			if d := c.backoff(n, 0); d < 0 || d > 40*time.Millisecond {
				t.Fatalf("backoff(%d) = %v", n, d)
			}
		}
	}
	if d := c.backoff(1, 3*time.Second); d < 3*time.Second {
		t.Errorf("Retry-After not honored: %v", d)
	}
}

func TestParseRetryAfter(t *testing.T) {
	if d := parseRetryAfter("7"); d != 7*time.Second {
		t.Errorf("seconds: %v", d)
	}
	if d := parseRetryAfter(time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)); d < 25*time.Second || d > 31*time.Second {
		t.Errorf("date: %v", d)
	}
	if d := parseRetryAfter("100000"); d != maxRetryAfter {
		t.Errorf("cap: %v", d)
	}
	if parseRetryAfter("garbage") != 0 || parseRetryAfter("") != 0 {
		t.Error("garbage should be 0")
	}
}

func TestErrorsIsSentinelsFromPipeline(t *testing.T) {
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	c, _ := newTestClient(t, srv, nil)
	err := c.REST(t.Context(), "GET", "/v3/x", nil, nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}
