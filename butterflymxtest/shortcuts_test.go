package butterflymxtest

import (
	"strings"
	"testing"
	"time"
)

func TestIssueAPIToken(t *testing.T) {
	s := newTestServer(t)
	tok := s.IssueAPIToken()
	if strings.Contains(tok, ".") || len(tok) < 300 {
		t.Errorf("token shape: %d chars", len(tok))
	}
	if tok2 := s.IssueAPIToken(); tok2 == tok {
		t.Error("tokens must be distinct")
	}
	wantStatus(t, api(t, s, tok, "GET", "/v3/access_codes", nil), 200)
	if n := len(s.Requests()); n != 1 {
		t.Errorf("shortcut must not record requests, saw %d", n)
	}
	s.RevokeAPITokens()
	wantStatus(t, api(t, s, tok, "GET", "/v3/access_codes", nil), 401)
	// A token issued after the revocation works again.
	wantStatus(t, api(t, s, s.IssueAPIToken(), "GET", "/v3/access_codes", nil), 200)
}

func TestIssueAPITokenHonorsTTL(t *testing.T) {
	now := fixedNow
	s := newTestServer(t, WithClock(func() time.Time { return now }), WithAPITokenTTL(time.Hour))
	tok := s.IssueAPIToken()
	wantStatus(t, api(t, s, tok, "GET", "/v3/access_codes", nil), 200)
	now = now.Add(61 * time.Minute)
	wantStatus(t, api(t, s, tok, "GET", "/v3/access_codes", nil), 401)
}

func TestIssueOAuthToken(t *testing.T) {
	now := fixedNow
	s := newTestServer(t, WithClock(func() time.Time { return now }), WithTokenTTL(time.Hour))
	access, refresh, expiry := s.IssueOAuthToken()
	if strings.Count(access, ".") != 2 || refresh == "" {
		t.Fatalf("access=%q refresh=%q", access, refresh)
	}
	if want := now.Add(time.Hour); !expiry.Equal(want) {
		t.Errorf("expiry = %v, want %v", expiry, want)
	}
	// The access token is accepted by the denizen login...
	if denizenLogin(t, s, access) == "" {
		t.Fatal("no API token")
	}
	// ...and the refresh token rotates.
	body := formBody("grant_type", "refresh_token", "refresh_token", refresh, "client_id", ClientID)
	hdr := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	r := do(t, newClient(), "POST", s.URL()+"/oauth/token", body, hdr)
	wantStatus(t, r, 200)
	if r.JSON(t)["refresh_token"] == refresh {
		t.Error("refresh token did not rotate")
	}
	wantStatus(t, do(t, newClient(), "POST", s.URL()+"/oauth/token", body, hdr), 400)

	// Expiry is honored by the server.
	now = now.Add(2 * time.Hour)
	b := `{"access_token":"` + access + `"}`
	wantStatus(t, do(t, newClient(), "POST", s.URL()+"/denizen/v1/login", []byte(b), map[string]string{"Content-Type": "application/json"}), 401)
}
