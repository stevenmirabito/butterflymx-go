package butterflymx

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stevenmirabito/butterflymx-go/auth"
	"github.com/stevenmirabito/butterflymx-go/butterflymxtest"
)

func TestEnvironmentForRegion(t *testing.T) {
	tests := []struct {
		in      string
		want    Environment
		wantErr bool
	}{
		{"na", Production, false},
		{"eu", ProductionEU, false},
		{"EU", ProductionEU, false},
		{" eu ", ProductionEU, false},
		{"Na", Production, false},
		{"", Environment{}, true},
		{"apac", Environment{}, true},
		{"bad", Environment{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := EnvironmentForRegion(tt.in)
			if tt.wantErr {
				if !errors.Is(err, ErrUnknownRegion) {
					t.Fatalf("err = %v, want ErrUnknownRegion", err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("got %+v, %v; want %+v", got, err, tt.want)
			}
		})
	}
}

func TestOptionsRegion(t *testing.T) {
	newClient := func(opts Options) (*Client, error) {
		opts.Auth = StaticAPIToken("t")
		return New(opts)
	}
	t.Run("eu", func(t *testing.T) {
		c, err := newClient(Options{Region: "eu"})
		if err != nil {
			t.Fatal(err)
		}
		if got := c.Environment(); got != ProductionEU || got.APIURL != "https://eu.api.butterflymx.com" {
			t.Errorf("Environment() = %+v", got)
		}
	})
	t.Run("na", func(t *testing.T) {
		c, err := newClient(Options{Region: " NA "})
		if err != nil {
			t.Fatal(err)
		}
		if c.Environment() != Production {
			t.Errorf("Environment() = %+v", c.Environment())
		}
	})
	t.Run("default", func(t *testing.T) {
		c, err := newClient(Options{})
		if err != nil {
			t.Fatal(err)
		}
		if c.Environment() != Production {
			t.Errorf("Environment() = %+v", c.Environment())
		}
	})
	t.Run("explicit environment wins", func(t *testing.T) {
		c, err := newClient(Options{Environment: Staging, Region: "eu"})
		if err != nil {
			t.Fatal(err)
		}
		if c.Environment() != Staging {
			t.Errorf("Environment() = %+v, want Staging", c.Environment())
		}
	})
	t.Run("bad region", func(t *testing.T) {
		if _, err := newClient(Options{Region: "mars"}); !errors.Is(err, ErrUnknownRegion) {
			t.Errorf("err = %v, want ErrUnknownRegion", err)
		}
		if _, err := newClient(Options{Environment: Staging, Region: "mars"}); !errors.Is(err, ErrUnknownRegion) {
			t.Errorf("with explicit Environment: err = %v, want ErrUnknownRegion", err)
		}
	})
}

func TestLocalEnvironment(t *testing.T) {
	e := LocalEnvironment("http://127.0.0.1:8080/")
	want := Environment{
		Name: "local", AccountsURL: "http://127.0.0.1:8080", APIURL: "http://127.0.0.1:8080",
		UnlockURL: "http://127.0.0.1:8080", IDPrefix: "prod",
	}
	if e != want {
		t.Errorf("LocalEnvironment = %+v, want %+v", e, want)
	}
	if err := e.Validate(); err != nil {
		t.Errorf("loopback http: %v", err)
	}
	if err := LocalEnvironment("http://proxy.example").Validate(); err == nil {
		t.Error("http for a non-loopback host was accepted")
	}
	if err := LocalEnvironment("https://proxy.example").Validate(); err != nil {
		t.Errorf("https proxy: %v", err)
	}
}

func TestEnvironmentValidateRejectsPlainHTTPForNonLoopback(t *testing.T) {
	for _, u := range []string{"http://api.butterflymx.com", "http://10.0.0.1", "http://192.168.1.2:8080", "http://localhost.example.com"} {
		env := Environment{Name: "x", AccountsURL: "https://a.example", APIURL: u}
		if err := env.Validate(); err == nil {
			t.Errorf("APIURL %q was accepted", u)
		}
		env = Environment{Name: "x", AccountsURL: "https://a.example", APIURL: "https://b.example", UnlockURL: u}
		if err := env.Validate(); err == nil {
			t.Errorf("UnlockURL %q was accepted", u)
		}
	}
	for _, u := range []string{"http://localhost:1", "http://127.0.0.1:1", "http://127.1.2.3", "http://[::1]:1"} {
		if err := LocalEnvironment(u).Validate(); err != nil {
			t.Errorf("%q: %v", u, err)
		}
	}
}

// authConfigShape clears the func and client fields of an auth.Config, which
// reflect.DeepEqual cannot compare.
func authConfigShape(c auth.Config) auth.Config {
	c.HTTPClient = nil
	c.Now = nil
	return c
}

func TestEnvironmentAuthConfigMatchesAuthPresets(t *testing.T) {
	for _, tt := range []struct {
		env  Environment
		want auth.Config
	}{
		{Production, auth.Production},
		{ProductionEU, auth.ProductionEU},
		{Staging, auth.Staging},
		{Sandbox, auth.Sandbox},
	} {
		t.Run(tt.env.Name, func(t *testing.T) {
			got, want := authConfigShape(tt.env.AuthConfig()), authConfigShape(tt.want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("AuthConfig() = %+v, want %+v", got, want)
			}
		})
	}
}

// TestLocalEnvironmentLogin logs in against the fake with nothing but
// LocalEnvironment and AuthConfig, then calls the API.
func TestLocalEnvironmentLogin(t *testing.T) {
	ctx := context.Background()
	srv := butterflymxtest.NewServer()
	t.Cleanup(srv.Close)
	env := LocalEnvironment(srv.URL())
	cfg := env.AuthConfig()

	res, err := auth.StartLogin(ctx, cfg, butterflymxtest.DefaultEmail, butterflymxtest.DefaultPassword)
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	if res.Challenge == nil {
		t.Fatalf("expected a challenge, got %+v", res)
	}
	tok, err := auth.CompleteLogin(ctx, cfg, res.Challenge, srv.CurrentTOTP())
	if err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	a := auth.NewAuthenticator(auth.AuthenticatorConfig{Config: cfg, Store: auth.NewMemoryTokenStore(tok)})
	c, err := New(Options{Environment: env, Auth: a})
	if err != nil {
		t.Fatal(err)
	}
	tenants, err := c.Tenants(ctx)
	if err != nil || len(tenants) == 0 {
		t.Fatalf("Tenants = %v, %v", tenants, err)
	}
}

// newSkipClient returns a client on a fresh fake, with SkipClientValidation
// set as asked, and the fake's tenant and a virtual-key door.
func newSkipClient(t *testing.T, skip bool) (*Client, *butterflymxtest.Server, CreateKeychainParams) {
	t.Helper()
	srv := butterflymxtest.NewServer()
	t.Cleanup(srv.Close)
	c, err := New(Options{
		Environment:          LocalEnvironment(srv.URL()),
		Auth:                 StaticAPIToken(srv.IssueAPIToken()),
		SkipClientValidation: skip,
		Retry:                RetryPolicy{MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	seed := srv.Seed()
	tenant, err := ParseGlobalID(seed.TenantGlobalID)
	if err != nil {
		t.Fatal(err)
	}
	door, err := ParseGlobalID(seed.VirtualKeyAccessPoints()[0].GlobalID)
	if err != nil {
		t.Fatal(err)
	}
	hour := time.Now().UTC().Truncate(time.Hour)
	return c, srv, CreateKeychainParams{
		TenantID: tenant, AccessPointIDs: []GlobalID{door}, Name: "Probe",
		Schedule:   CustomSchedule{StartsAt: hour.Add(time.Hour), EndsAt: hour.Add(2 * time.Hour)},
		Recipients: []Recipient{EmailRecipient("A", "a@example.com")},
	}
}

func TestSkipClientValidation(t *testing.T) {
	hour := time.Now().UTC().Truncate(time.Hour)
	cases := []struct {
		name        string
		mod         func(*CreateKeychainParams)
		wantPointer string // suffix of the first error's source.pointer
	}{
		{"end before start", func(p *CreateKeychainParams) {
			p.Schedule = CustomSchedule{StartsAt: hour.Add(2 * time.Hour), EndsAt: hour.Add(time.Hour)}
		}, "ends_at"},
		{"invalid recipient", func(p *CreateKeychainParams) {
			p.Recipients = []Recipient{{Name: "A", DeliverTo: "not-an-address"}}
		}, "recipients/0/deliver_to"},
		{"blank name", func(p *CreateKeychainParams) { p.Name = "  " }, "name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			// Default: rejected before any request is made.
			c, srv, p := newSkipClient(t, false)
			tc.mod(&p)
			before := len(srv.Requests())
			_, err := c.CreateKeychain(ctx, p)
			var e *Error
			if !errors.Is(err, ErrValidation) || !errors.As(err, &e) || e.StatusCode != 0 {
				t.Fatalf("default: err = %#v, want a client-side ErrValidation", err)
			}
			if n := len(srv.Requests()); n != before {
				t.Fatalf("default: %d requests reached the server", n-before)
			}

			// With the option the server answers.
			c, srv, p = newSkipClient(t, true)
			tc.mod(&p)
			before = len(srv.Requests())
			_, err = c.CreateKeychain(ctx, p)
			if !errors.Is(err, ErrValidation) || !errors.As(err, &e) {
				t.Fatalf("skip: err = %#v, want ErrValidation", err)
			}
			if e.StatusCode != http.StatusBadRequest || len(e.APIErrors) == 0 {
				t.Fatalf("skip: error = %#v, want HTTP 400 with API errors", e)
			}
			var found bool
			for _, a := range e.APIErrors {
				if a.Detail == "" || a.Source == nil {
					t.Errorf("API error lacks detail or pointer: %+v", a)
				}
				if a.Source != nil && strings.HasSuffix(a.Source.Pointer, tc.wantPointer) {
					found = true
				}
			}
			if !found {
				t.Errorf("no error pointer ends in %q: %+v", tc.wantPointer, e.APIErrors)
			}
			if n := len(srv.Requests()); n != before+1 {
				t.Errorf("skip: %d requests reached the server, want 1", n-before)
			}
			if n := len(srv.Keychains()); n != len(srv.Seed().ActiveKeychainIDs)+len(srv.Seed().ExpiredKeychainIDs) {
				t.Errorf("rejected request left %d keychains", n)
			}
		})
	}
}

// IDs are converted to build the request, so skipping validation must not
// turn a wrong ID type into a request.
func TestSkipClientValidationKeepsIDConversions(t *testing.T) {
	c, srv, p := newSkipClient(t, true)
	p.TenantID = NewGlobalID("prod", TypeUnit, 1)
	before := len(srv.Requests())
	if _, err := c.CreateKeychain(context.Background(), p); !errors.Is(err, ErrIDType) {
		t.Errorf("err = %v, want ErrIDType", err)
	}
	if n := len(srv.Requests()); n != before {
		t.Errorf("%d requests sent", n-before)
	}
}

func TestSkipClientValidationAddVirtualKeys(t *testing.T) {
	ctx := context.Background()
	c, srv, p := newSkipClient(t, false)
	pass, err := c.CreateKeychain(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	bad := Recipient{Name: "B", DeliverTo: "nope"}
	before := len(srv.Requests())
	if _, err := c.AddVirtualKeys(ctx, pass.ID, bad); !errors.Is(err, ErrValidation) {
		t.Fatalf("default: err = %v", err)
	}
	if n := len(srv.Requests()); n != before {
		t.Fatalf("default: %d requests sent", n-before)
	}

	c, srv, p = newSkipClient(t, true)
	if pass, err = c.CreateKeychain(ctx, p); err != nil {
		t.Fatal(err)
	}
	before = len(srv.Requests())
	_, err = c.AddVirtualKeys(ctx, pass.ID, bad)
	var e *Error
	if !errors.Is(err, ErrValidation) || !errors.As(err, &e) || e.StatusCode != http.StatusBadRequest {
		t.Fatalf("skip: err = %#v, want a server 400", err)
	}
	if n := len(srv.Requests()); n != before+1 {
		t.Errorf("skip: %d requests sent, want 1", n-before)
	}
}
