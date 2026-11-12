package butterflymx

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRawGraphQL(t *testing.T) {
	var body string
	var service string
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body, service = string(b), r.Header.Get("x-bmx-service")
		_, _ = w.Write([]byte(`{"data":{"hello":"world"}}`))
	})
	c, _ := newTestClient(t, srv, nil)
	var out struct {
		Hello string `json:"hello"`
	}
	err := c.GraphQL(t.Context(), "Hello", "query Hello { hello }", map[string]any{"a": 1}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if out.Hello != "world" || service != "denizen-api" {
		t.Errorf("out=%+v service=%q", out, service)
	}
	for _, s := range []string{`"operationName":"Hello"`, `"query":"query Hello { hello }"`, `"variables":{"a":1}`} {
		if !strings.Contains(body, s) {
			t.Errorf("body missing %s: %s", s, body)
		}
	}
}

func TestRawREST(t *testing.T) {
	var method, path, query, body string
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		method, path, query, body = r.Method, r.URL.Path, r.URL.RawQuery, string(b)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"id":"5"}}`))
	})
	c, _ := newTestClient(t, srv, nil)
	var out map[string]map[string]string
	err := c.REST(t.Context(), "POST", "/v3/things", map[string][]string{"x": {"1"}}, map[string]any{"k": "v"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if method != "POST" || path != "/v3/things" || query != "x=1" || body != `{"k":"v"}` || out["data"]["id"] != "5" {
		t.Errorf("method=%s path=%s query=%s body=%s out=%v", method, path, query, body, out)
	}
}

func TestRawRESTNoContentAndErrors(t *testing.T) {
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gone" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	c, _ := newTestClient(t, srv, nil)
	var out map[string]any
	if err := c.REST(t.Context(), "DELETE", "/v3/x/1", nil, nil, &out); err != nil || out != nil {
		t.Errorf("204: out=%v err=%v", out, err)
	}
	if err := c.REST(t.Context(), "GET", "/gone", nil, nil, nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v", err)
	}
	if err := c.REST(t.Context(), "GET", "v3/x", nil, nil, nil); err == nil {
		t.Error("relative path without slash should fail")
	}
}

func TestRawRESTBadJSON(t *testing.T) {
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>")) })
	c, _ := newTestClient(t, srv, nil)
	var out map[string]any
	if err := c.REST(t.Context(), "GET", "/v3/x", nil, nil, &out); err == nil {
		t.Error("expected decode error")
	}
}
