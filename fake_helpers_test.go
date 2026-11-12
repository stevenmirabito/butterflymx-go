package butterflymx

import (
	"testing"
	"time"

	"github.com/stevenmirabito/butterflymx-go/butterflymxtest"
)

// newFakeClient starts a butterflymxtest server (configured by opts) and
// returns a Client wired to it with a pre-issued API token, so tests of API
// calls do not repeat the login flow. Retries are fast.
func newFakeClient(t *testing.T, opts ...butterflymxtest.Option) (*Client, *butterflymxtest.Server) {
	t.Helper()
	srv := butterflymxtest.NewServer(opts...)
	t.Cleanup(srv.Close)
	c, err := New(Options{
		Environment: LocalEnvironment(srv.URL()),
		Auth:        StaticAPIToken(srv.IssueAPIToken()),
		Retry:       RetryPolicy{MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, srv
}
