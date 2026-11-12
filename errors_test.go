package butterflymx

import (
	"encoding/json/v2"
	"errors"
	"io"
	"testing"
)

func TestErrorIs(t *testing.T) {
	sentinels := []error{ErrUnauthorized, ErrForbidden, ErrNotFound, ErrConflict, ErrValidation, ErrRateLimited, ErrServer, ErrNotSupported}
	tests := []struct {
		status int
		want   error
	}{
		{401, ErrUnauthorized}, {403, ErrForbidden}, {404, ErrNotFound}, {409, ErrConflict},
		{400, ErrValidation}, {422, ErrValidation}, {429, ErrRateLimited},
		{500, ErrServer}, {502, ErrServer}, {503, ErrServer}, {599, ErrServer},
		{200, nil}, {0, nil}, {418, nil}, {600, nil},
	}
	for _, tt := range tests {
		err := error(&Error{Op: "X", StatusCode: tt.status})
		for _, s := range sentinels {
			if got, want := errors.Is(err, s), errors.Is(s, tt.want); got != want {
				t.Errorf("status %d: errors.Is(%v) = %v, want %v", tt.status, s, got, want)
			}
		}
	}
}

func TestErrorUnwrap(t *testing.T) {
	err := &Error{Op: "Login", Err: io.ErrUnexpectedEOF}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Error("should unwrap")
	}
	var e *Error
	if !errors.As(error(err), &e) {
		t.Error("errors.As")
	}
}

func TestErrorString(t *testing.T) {
	tests := []struct {
		name string
		err  *Error
		want string
	}{
		{"detail", &Error{Op: "CreateKeychain", Method: "POST", URL: "https://api.butterflymx.com/v3/keychains/custom?x=1", StatusCode: 400,
			APIErrors: []APIErrorObject{{Title: "Invalid", Detail: "ends_at must be after starts_at"}}},
			"butterflymx: CreateKeychain: POST /v3/keychains/custom: 400: ends_at must be after starts_at"},
		{"title", &Error{Op: "Get", Method: "GET", URL: "/v3/x", StatusCode: 404, APIErrors: []APIErrorObject{{Title: "Not Found"}}},
			"butterflymx: Get: GET /v3/x: 404: Not Found"},
		{"graphql", &Error{Op: "Tenants", Method: "POST", URL: "https://api.butterflymx.com/graphql",
			GraphQLErrors: []GraphQLError{{Message: "boom"}}},
			"butterflymx: Tenants: POST /graphql: boom"},
		{"transport", &Error{Op: "Login", Method: "GET", URL: "https://accounts.butterflymx.com/login", Err: io.EOF},
			"butterflymx: Login: GET /login: EOF"},
		{"bare status", &Error{Op: "Do", Method: "GET", URL: "/p", StatusCode: 500},
			"butterflymx: Do: GET /p: 500"},
		{"pointer and detail only", &Error{Op: "CreateKeychain", Method: "POST", URL: "/v3/keychains/custom", StatusCode: 400,
			APIErrors: []APIErrorObject{{Detail: "cannot exceed 365 days from start date", Source: &APIErrorSource{Pointer: "/data/attributes/ends_at"}}}},
			"butterflymx: CreateKeychain: POST /v3/keychains/custom: 400: cannot exceed 365 days from start date"},
		{"html", &Error{Op: "Get", Method: "GET", URL: "/v3/x", StatusCode: 404, Body: []byte("<!DOCTYPE html>\n<html><body>nope</body></html>")},
			"butterflymx: Get: GET /v3/x: 404: unexpected HTML response"},
		{"minimal", &Error{}, "butterflymx"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestErrorObjectJSON(t *testing.T) {
	var got struct {
		Errors []APIErrorObject `json:"errors"`
	}
	in := `{"errors":[{"status":"400","code":"blank","title":"Invalid","detail":"can't be blank","source":{"pointer":"/data/attributes/name","parameter":"q"}}]}`
	if err := json.Unmarshal([]byte(in), &got); err != nil {
		t.Fatal(err)
	}
	e := got.Errors[0]
	if e.Status != "400" || e.Code != "blank" || e.Title != "Invalid" || e.Detail != "can't be blank" ||
		e.Source == nil || e.Source.Pointer != "/data/attributes/name" || e.Source.Parameter != "q" {
		t.Errorf("got %+v", e)
	}
	var g GraphQLError
	if err := json.Unmarshal([]byte(`{"message":"m","path":["a",0],"extensions":{"code":"X"}}`), &g); err != nil {
		t.Fatal(err)
	}
	if g.Message != "m" || len(g.Path) != 2 || g.Extensions["code"] != "X" {
		t.Errorf("got %+v", g)
	}
}
