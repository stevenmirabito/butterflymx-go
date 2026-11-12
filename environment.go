package butterflymx

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/stevenmirabito/butterflymx-go/auth"
)

// DefaultUserAgent mimics the official iOS app's User-Agent.
const DefaultUserAgent = "butterflymx/1001.125.2 (com.butterflymx.butterflymx; build:1266; iOS 27.2.0) Alamofire/5.10.2"

// Environment describes one ButterflyMX deployment.
type Environment struct {
	Name        string // "production", "production-eu", "staging", "sandbox"
	AccountsURL string // OAuth / login host, no trailing slash
	APIURL      string // REST /v3, /mobile/v4, GraphQL, denizen
	UnlockURL   string // unlock service; "" when unknown for this environment
	IDPrefix    string // global-ID env prefix, "prod" in production; "" when unknown
}

// Known environments. Only Production is confirmed from captured traffic; the
// others are taken from the iOS app's configuration.
var (
	Production = Environment{
		Name:        "production",
		AccountsURL: "https://accounts.butterflymx.com",
		APIURL:      "https://api.butterflymx.com",
		UnlockURL:   "https://api.unlock.prod.butterflymx.com",
		IDPrefix:    "prod",
	}
	ProductionEU = Environment{
		Name:        "production-eu",
		AccountsURL: "https://accounts.butterflymx.com",
		APIURL:      "https://eu.api.butterflymx.com",
		IDPrefix:    "prod",
	}
	Staging = Environment{
		Name:        "staging",
		AccountsURL: "https://accounts.na.staging.butterflymx.com",
		APIURL:      "https://api.na.staging.butterflymx.com",
	}
	Sandbox = Environment{
		Name:        "sandbox",
		AccountsURL: "https://accounts.na.sandbox.butterflymx.com",
		APIURL:      "https://api.na.sandbox.butterflymx.com",
	}
)

// EnvironmentForRegion returns the production environment of a region: "na"
// is [Production] and "eu" is [ProductionEU]. The match ignores case and
// surrounding spaces. Any other value returns an error wrapping
// [ErrUnknownRegion].
//
// The region of a signed-in account is [auth.Token].Region, so a program can
// pass that value here (or to [Options.Region]) to talk to the right API host.
func EnvironmentForRegion(region string) (Environment, error) {
	switch strings.ToLower(strings.TrimSpace(region)) {
	case "na":
		return Production, nil
	case "eu":
		return ProductionEU, nil
	}
	return Environment{}, fmt.Errorf("%w: %q (want \"na\" or \"eu\")", ErrUnknownRegion, region)
}

// LocalEnvironment returns an environment in which the accounts host, the API
// host and the unlock host are all baseURL (a trailing slash is trimmed). It
// is for talking to the fake in package butterflymxtest, to a proxy, or to any
// other single-host setup. Its Name is "local" and its IDPrefix is "prod".
//
// [Environment.Validate] accepts plain http only for loopback hosts
// (localhost, 127.0.0.0/8, ::1), so a baseURL such as "http://127.0.0.1:8080"
// works but "http://proxy.example" does not; use https there.
func LocalEnvironment(baseURL string) Environment {
	u := strings.TrimRight(baseURL, "/")
	return Environment{Name: "local", AccountsURL: u, APIURL: u, UnlockURL: u, IDPrefix: "prod"}
}

// AuthConfig returns the [auth.Config] for the environment's accounts and API
// hosts, so that the login and the client talk to the same deployment:
//
//	env := butterflymx.ProductionEU
//	res, err := auth.StartLogin(ctx, env.AuthConfig(), email, password)
//
// It is [auth.ConfigFor] of AccountsURL and APIURL; set the optional fields
// (HTTPClient, Now and so on) on the returned value.
func (e Environment) AuthConfig() auth.Config {
	return auth.ConfigFor(e.AccountsURL, e.APIURL)
}

// Validate checks that the URLs are absolute https URLs. UnlockURL may be empty.
//
// Plain http is accepted only for loopback hosts (localhost, 127.0.0.0/8,
// ::1), so that clients can talk to a local fake such as the one in package
// butterflymxtest.
func (e Environment) Validate() error {
	for _, f := range []struct {
		name, val string
		optional  bool
	}{
		{"AccountsURL", e.AccountsURL, false},
		{"APIURL", e.APIURL, false},
		{"UnlockURL", e.UnlockURL, true},
	} {
		if f.val == "" {
			if f.optional {
				continue
			}
			return fmt.Errorf("butterflymx: environment %q: %s is empty", e.Name, f.name)
		}
		u, err := url.Parse(f.val)
		if err != nil {
			return fmt.Errorf("butterflymx: environment %q: %s: %w", e.Name, f.name, err)
		}
		if u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || !envIsLoopback(u.Hostname()))) {
			return fmt.Errorf("butterflymx: environment %q: %s %q is not an absolute https URL (plain http is allowed only for loopback hosts)", e.Name, f.name, f.val)
		}
	}
	return nil
}

// envIsLoopback reports whether host is localhost or a loopback IP address.
func envIsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
