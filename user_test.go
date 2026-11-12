package butterflymx

import (
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"testing"
)

// gqlTestOps serves GraphQL operations over TLS. ops maps an operation name
// to a function that returns the response body for the request variables.
// The returned slice records the variables of every request, per operation.
func gqlTestOps(t *testing.T, ops map[string]func(vars map[string]any) []byte) (*Client, *[]map[string]any) {
	t.Helper()
	var seen []map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			OperationName string         `json:"operationName"`
			Variables     map[string]any `json:"variables"`
		}
		if err := json.UnmarshalRead(r.Body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		seen = append(seen, req.Variables)
		f, ok := ops[req.OperationName]
		if !ok {
			http.Error(w, "unexpected op "+req.OperationName, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(f(req.Variables))
	}))
	t.Cleanup(srv.Close)
	c, _ := newTestClient(t, srv, nil)
	return c, &seen
}

// gqlTestFixture returns an op handler that always serves a recorded response.
func gqlTestFixture(t *testing.T, name string) func(map[string]any) []byte {
	t.Helper()
	body := fixtureBody(t, "graphql/"+name+".json")
	return func(map[string]any) []byte { return body }
}

func TestGQLCurrentUserFixture(t *testing.T) {
	c, _ := gqlTestOps(t, map[string]func(map[string]any) []byte{"CurrentUser": gqlTestFixture(t, "CurrentUser")})
	u, err := c.CurrentUser(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if u.ID.String() != "prod-user-563494348" || u.ID.Type != TypeUser {
		t.Errorf("ID = %v", u.ID)
	}
	if u.FirstName != "Resident" || u.LastName != "Example" || u.Email != "resident@example.com" ||
		u.PhoneNumber != "5555550100" || u.ContactPreference != "VIDEO_CALL" ||
		u.AvatarURL != "https://example.com/avatar.jpg" || u.AcknowledgedPrivacyPolicyVersion != "2026-01-23" {
		t.Errorf("user = %+v", u)
	}
	if u.HasDormakabaSmartLock {
		t.Error("HasDormakabaSmartLock = true")
	}
	if !u.TwoFactor.Enabled || u.TwoFactor.Required || len(u.TwoFactor.Types) != 3 || u.TwoFactor.Types[2] != "AUTHENTICATOR_APP" {
		t.Errorf("TwoFactor = %+v", u.TwoFactor)
	}
}

func TestGQLCurrentUserNull(t *testing.T) {
	c, _ := gqlTestOps(t, map[string]func(map[string]any) []byte{
		"CurrentUser": func(map[string]any) []byte { return []byte(`{"data":{"currentUser":null}}`) },
	})
	if _, err := c.CurrentUser(context.Background()); !isNotFound(err) {
		t.Fatalf("err = %v, want not found", err)
	}
}
