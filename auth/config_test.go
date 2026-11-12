package auth

import (
	"reflect"
	"testing"
)

// comparable strips the func and HTTP fields.
func comparableConfig(c Config) Config {
	c.HTTPClient, c.Now = nil, nil
	return c
}

func TestPresetsAreConfigFor(t *testing.T) {
	for _, tc := range []struct {
		name     string
		got      Config
		accounts string
		api      string
	}{
		{"Production", Production, "https://accounts.butterflymx.com", "https://api.butterflymx.com"},
		{"ProductionEU", ProductionEU, "https://accounts.butterflymx.com", "https://eu.api.butterflymx.com"},
		{"Staging", Staging, "https://accounts.na.staging.butterflymx.com", "https://api.na.staging.butterflymx.com"},
		{"Sandbox", Sandbox, "https://accounts.na.sandbox.butterflymx.com", "https://api.na.sandbox.butterflymx.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := ConfigFor(tc.accounts, tc.api)
			if !reflect.DeepEqual(comparableConfig(tc.got), comparableConfig(want)) {
				t.Errorf("preset = %+v\nConfigFor = %+v", tc.got, want)
			}
			if want.AccountsURL != tc.accounts || want.APIURL != tc.api {
				t.Errorf("URLs = %q, %q", want.AccountsURL, want.APIURL)
			}
			if want.HTTPClient != nil || want.Now != nil {
				t.Error("ConfigFor must leave HTTPClient and Now unset")
			}
			// Defaults are applied to the same values as withDefaults.
			if !reflect.DeepEqual(comparableConfig(want), comparableConfig(want.withDefaults())) {
				t.Error("ConfigFor is not fully defaulted")
			}
		})
	}
}

func TestConfigForValues(t *testing.T) {
	c := ConfigFor("http://127.0.0.1:1234/", "http://127.0.0.1:5678//")
	if c.AccountsURL != "http://127.0.0.1:1234" || c.APIURL != "http://127.0.0.1:5678" {
		t.Errorf("URLs = %q, %q", c.AccountsURL, c.APIURL)
	}
	if c.ClientID != publicClientID || c.RedirectURI != publicRedirectURI || c.Scope != publicScope ||
		c.UserAgent != DefaultUserAgent || c.WebUserAgent != DefaultWebUserAgent ||
		c.Device.Platform != "ios" || c.Device.Version != "1001.125.2" || len(c.Device.Locales) != 1 {
		t.Errorf("defaults = %+v", c)
	}
	// Each call returns independent slices.
	c.Device.Locales[0] = "xx"
	if ConfigFor("a", "b").Device.Locales[0] != "en-US" {
		t.Error("Locales shared between configs")
	}
}
