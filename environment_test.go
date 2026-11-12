package butterflymx

import "testing"

func TestEnvironments(t *testing.T) {
	for _, e := range []Environment{Production, ProductionEU, Staging, Sandbox} {
		if err := e.Validate(); err != nil {
			t.Errorf("%s: %v", e.Name, err)
		}
	}
	if Production.UnlockURL == "" || Production.IDPrefix != "prod" {
		t.Errorf("bad production: %+v", Production)
	}
	if ProductionEU.UnlockURL != "" || ProductionEU.IDPrefix != "prod" || ProductionEU.APIURL != "https://eu.api.butterflymx.com" {
		t.Errorf("bad EU: %+v", ProductionEU)
	}
}

func TestEnvironmentValidate(t *testing.T) {
	tests := []struct {
		name    string
		env     Environment
		wantErr bool
	}{
		{"ok no unlock", Environment{AccountsURL: "https://a.example", APIURL: "https://b.example"}, false},
		{"http", Environment{AccountsURL: "http://a.example", APIURL: "https://b.example"}, true},
		{"relative", Environment{AccountsURL: "a.example", APIURL: "https://b.example"}, true},
		{"empty api", Environment{AccountsURL: "https://a.example"}, true},
		{"bad unlock", Environment{AccountsURL: "https://a.example", APIURL: "https://b.example", UnlockURL: "ftp://x"}, true},
		{"unparsable", Environment{AccountsURL: "https://a.example", APIURL: "https://b\x7f.example"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.env.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
