package butterflymx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stevenmirabito/butterflymx-go/internal/graphql"
	"github.com/stevenmirabito/butterflymx-go/internal/jsonapi"
)

func TestHeaders(t *testing.T) {
	var got http.Header
	var gotBody []byte
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	})
	c, _ := newTestClient(t, srv, func(o *Options) { o.UserAgent = "ua-test" })

	_, _, _, err := c.do(t.Context(), call{Op: "T", Method: "POST", Path: "/v3/x", Body: []byte(`{}`), ContentType: contentTypeJSON})
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"User-Agent": "ua-test", "Accept": "*/*", "Accept-Language": "en-US;q=1.0",
		"Content-Type": "application/json", "Authorization": "Bearer tok",
	} {
		if got.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, got.Get(k), want)
		}
	}
	if string(gotBody) != "{}" {
		t.Errorf("body = %q", gotBody)
	}

	// No body: no Content-Type.
	if _, _, _, err := c.do(t.Context(), call{Op: "T", Method: "GET", Path: "/v3/x"}); err != nil {
		t.Fatal(err)
	}
	if ct := got.Get("Content-Type"); ct != "" {
		t.Errorf("Content-Type = %q on bodyless request", ct)
	}
}

func TestGraphQLHeadersAndBody(t *testing.T) {
	var got http.Header
	var gotBody []byte
	var path string
	resp := fixtureBody(t, "graphql/CurrentUser.json")
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		got, path = r.Header.Clone(), r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write(resp)
	})
	c, _ := newTestClient(t, srv, nil)
	var data struct {
		CurrentUser struct {
			ID string `json:"id"`
		} `json:"currentUser"`
	}
	if err := c.graphQL(t.Context(), "CurrentUser", graphql.CurrentUser, nil, &data); err != nil {
		t.Fatal(err)
	}
	if data.CurrentUser.ID == "" {
		t.Error("data not decoded")
	}
	if path != "/denizen/v1/graphql" {
		t.Errorf("path = %q", path)
	}
	if got.Get("X-Bmx-Service") != "denizen-api" || got.Get("Accept") != "application/json" || got.Get("Content-Type") != "application/json" {
		t.Errorf("headers = %v", got)
	}
	for _, s := range []string{`"operationName":"CurrentUser"`, `"apollo-ios"`, `"query"`} {
		if !bytes.Contains(gotBody, []byte(s)) {
			t.Errorf("body missing %s: %s", s, gotBody)
		}
	}
}

func TestUnauthorizedRetriesOnceWithFreshToken(t *testing.T) {
	auth := &recordingAuth{}
	var tokens []string
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		tokens = append(tokens, r.Header.Get("Authorization"))
		if len(tokens) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	c, _ := newTestClient(t, srv, func(o *Options) { o.Auth = auth })
	// POST: the re-auth retry applies to every method.
	if _, _, _, err := c.do(t.Context(), call{Op: "T", Method: "POST", Path: "/v3/x", Body: []byte("{}"), ContentType: contentTypeJSON}); err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 || tokens[0] != "Bearer tok-1" || tokens[1] != "Bearer tok-2" {
		t.Errorf("tokens = %v", tokens)
	}
	if len(auth.invalidated) != 1 || auth.invalidated[0] != "tok-1" {
		t.Errorf("invalidated = %v", auth.invalidated)
	}
}

func TestUnauthorizedTwice(t *testing.T) {
	auth := &recordingAuth{}
	var n atomic.Int32
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	})
	c, _ := newTestClient(t, srv, func(o *Options) { o.Auth = auth })
	_, _, _, err := c.do(t.Context(), call{Op: "T", Method: "GET", Path: "/v3/x", Idempotent: true})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v", err)
	}
	if n.Load() != 2 || len(auth.invalidated) != 1 {
		t.Errorf("requests = %d, invalidations = %v", n.Load(), auth.invalidated)
	}
	var e *Error
	if !errors.As(err, &e) || e.StatusCode != http.StatusUnauthorized || e.Op != "T" || e.Method != http.MethodGet || e.URL != "/v3/x" {
		t.Errorf("error fields = %+v", e)
	}
}

func TestGETRetriedOn503(t *testing.T) {
	var n atomic.Int32
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	c, delays := newTestClient(t, srv, nil)
	var out struct {
		OK bool `json:"ok"`
	}
	if err := c.doJSON(t.Context(), "T", "GET", apiBase, "/v3/x", nil, &out); err != nil {
		t.Fatal(err)
	}
	if !out.OK || n.Load() != 3 || len(*delays) != 2 {
		t.Errorf("ok=%v requests=%d delays=%v", out.OK, n.Load(), *delays)
	}
}

func TestGETGivesUpAfterMaxAttempts(t *testing.T) {
	var n atomic.Int32
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	})
	c, _ := newTestClient(t, srv, func(o *Options) { o.Retry.MaxAttempts = 3 })
	err := c.doJSON(t.Context(), "T", "GET", apiBase, "/v3/x", nil, nil)
	if !errors.Is(err, ErrServer) || n.Load() != 3 {
		t.Errorf("err=%v requests=%d", err, n.Load())
	}
}

func TestPOSTNotRetriedOn503(t *testing.T) {
	var n atomic.Int32
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c, delays := newTestClient(t, srv, nil)
	err := c.doJSON(t.Context(), "T", "POST", apiBase, "/v3/x", map[string]any{"a": 1}, nil)
	if !errors.Is(err, ErrServer) || n.Load() != 1 || len(*delays) != 0 {
		t.Errorf("err=%v requests=%d delays=%v", err, n.Load(), *delays)
	}
}

func TestRetryAfterHonored(t *testing.T) {
	var n atomic.Int32
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	c, delays := newTestClient(t, srv, nil)
	if err := c.doJSON(t.Context(), "T", "GET", apiBase, "/v3/x", nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(*delays) != 1 || (*delays)[0] < 2*time.Second {
		t.Errorf("delays = %v", *delays)
	}
}

func TestRateLimitedFinalError(t *testing.T) {
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTooManyRequests) })
	c, _ := newTestClient(t, srv, func(o *Options) { o.Retry.MaxAttempts = 2 })
	err := c.doJSON(t.Context(), "T", "GET", apiBase, "/v3/x", nil, nil)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v", err)
	}
}

func TestDELETE404AfterRetryIsSuccess(t *testing.T) {
	var n atomic.Int32
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	c, _ := newTestClient(t, srv, nil)
	if err := c.doJSON(t.Context(), "T", "DELETE", apiBase, "/v3/x/1", nil, nil); err != nil {
		t.Fatalf("err = %v", err)
	}
}

func TestDELETE404FirstAttemptIsError(t *testing.T) {
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	c, _ := newTestClient(t, srv, nil)
	err := c.doJSON(t.Context(), "T", "DELETE", apiBase, "/v3/x/1", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestNetworkErrorRetriedForIdempotent(t *testing.T) {
	var n atomic.Int32
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			panic(http.ErrAbortHandler) // closes the connection
		}
		w.WriteHeader(http.StatusNoContent)
	})
	c, _ := newTestClient(t, srv, nil)
	if err := c.doJSON(t.Context(), "T", "GET", apiBase, "/v3/x", nil, nil); err != nil {
		t.Fatal(err)
	}
	if n.Load() != 2 {
		t.Errorf("requests = %d", n.Load())
	}
	// POST is not retried.
	n.Store(0)
	err := c.doJSON(t.Context(), "T", "POST", apiBase, "/v3/x", nil, nil)
	if err == nil || n.Load() != 1 {
		t.Errorf("err=%v requests=%d", err, n.Load())
	}
}

func TestContextCancelStopsRetries(t *testing.T) {
	var n atomic.Int32
	ctx, cancel := context.WithCancel(t.Context())
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c, _ := newTestClient(t, srv, nil)
	c.sleep = func(ctx context.Context, d time.Duration) error {
		cancel()
		return sleepCtx(ctx, time.Hour)
	}
	err := c.doJSON(ctx, "T", "GET", apiBase, "/v3/x", nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if n.Load() != 1 {
		t.Errorf("requests = %d", n.Load())
	}
}

func TestSleepCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := sleepCtx(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
	if err := sleepCtx(t.Context(), time.Millisecond); err != nil {
		t.Error(err)
	}
}

func TestGraphQLPartialError(t *testing.T) {
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"x":1},"errors":[{"message":"field boom","path":["a"]}]}`))
	})
	var logs bytes.Buffer
	c, _ := newTestClient(t, srv, func(o *Options) {
		o.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	var d struct {
		X int `json:"x"`
	}
	if err := c.graphQL(t.Context(), "Q", graphql.CurrentUser, nil, &d); err != nil {
		t.Fatal(err)
	}
	if d.X != 1 {
		t.Errorf("data = %+v", d)
	}
	if !strings.Contains(logs.String(), "level=WARN") {
		t.Errorf("partial errors not logged at Warn: %s", logs.String())
	}
}

func TestGraphQLNullDataError(t *testing.T) {
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":null,"errors":[{"message":"not allowed","extensions":{"code":"FORBIDDEN"}}]}`))
	})
	c, _ := newTestClient(t, srv, nil)
	err := c.graphQL(t.Context(), "Q", graphql.CurrentUser, nil, nil)
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %v", err)
	}
	if len(e.GraphQLErrors) != 1 || e.GraphQLErrors[0].Message != "not allowed" || e.GraphQLErrors[0].Extensions["code"] != "FORBIDDEN" {
		t.Errorf("GraphQLErrors = %+v", e.GraphQLErrors)
	}
	if e.Op != "Q" || e.StatusCode != 0 {
		t.Errorf("error = %+v", e)
	}
}

func TestJSONAPIValidationError(t *testing.T) {
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":[{"status":"400","title":"Invalid","detail":"name is too short","source":{"pointer":"/data/attributes/name"}}]}`))
	})
	c, _ := newTestClient(t, srv, nil)
	_, err := c.jsonAPI(t.Context(), "Create", "POST", "/v3/keychains/custom", url.Values{"secret": {"q-value"}},
		&jsonapi.ResourceObject{Type: "keychains", Attributes: map[string]any{"name": "x"}})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("err = %v", err)
	}
	var e *Error
	if !errors.As(err, &e) || len(e.APIErrors) != 1 {
		t.Fatalf("error = %+v", e)
	}
	ae := e.APIErrors[0]
	if ae.Detail != "name is too short" || ae.Source == nil || ae.Source.Pointer != "/data/attributes/name" || ae.Status != "400" {
		t.Errorf("api error = %+v", ae)
	}
	if e.URL != "/v3/keychains/custom" || strings.Contains(e.Error(), "q-value") {
		t.Errorf("URL = %q, msg = %q", e.URL, e.Error())
	}
}

func TestErrorBodyTruncated(t *testing.T) {
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(bytes.Repeat([]byte("x"), 200<<10))
	})
	c, _ := newTestClient(t, srv, nil)
	_, _, _, err := c.do(t.Context(), call{Op: "T", Method: "POST", Path: "/v3/x"})
	var e *Error
	if !errors.As(err, &e) || len(e.Body) != 2<<10 {
		t.Fatalf("err = %v, body len = %d", err, len(e.Body))
	}
}

func TestJSONAPIFixtureAndRequestShape(t *testing.T) {
	resp := fixtureBody(t, "rest/post-keychains-custom-201.json")
	var gotBody []byte
	var gotQuery string
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(resp)
	})
	c, _ := newTestClient(t, srv, nil)
	doc, err := c.jsonAPI(t.Context(), "Create", "POST", "/v3/keychains/custom", url.Values{"include": {"virtual_keys"}},
		&jsonapi.ResourceObject{Type: "keychains", Attributes: map[string]any{"name": "x"}, Relationships: map[string]jsonapi.RelationshipObject{"tenant": jsonapi.ToOne("tenants", "1")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := doc.One(); err != nil {
		t.Errorf("fixture document: %v", err)
	}
	if gotQuery != "include=virtual_keys" || !bytes.Contains(gotBody, []byte(`"type":"keychains"`)) {
		t.Errorf("query=%q body=%s", gotQuery, gotBody)
	}
}

func TestJSONAPI204NilDocument(t *testing.T) {
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	c, _ := newTestClient(t, srv, nil)
	doc, err := c.jsonAPI(t.Context(), "Del", "DELETE", "/v3/keychains/1", nil, nil)
	if err != nil || doc != nil {
		t.Fatalf("doc=%v err=%v", doc, err)
	}
}

func TestDoJSONUnlockFixture(t *testing.T) {
	resp := fixtureBody(t, "unlock/post-access-point-200.json")
	var path string
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = w.Write(resp)
	})
	c, _ := newTestClient(t, srv, nil)
	var out struct {
		RequestID string `json:"requestId"`
	}
	in := map[string]string{"accessPointId": "prod-access_point-1", "source": "mobile_app", "tenantId": "prod-tenant-1"}
	if err := c.doJSON(t.Context(), "Unlock", "POST", unlockBase, "/v1/access-point", in, &out); err != nil {
		t.Fatal(err)
	}
	if out.RequestID == "" || path != "/v1/access-point" {
		t.Errorf("out=%+v path=%q", out, path)
	}
}

func TestUnlockNotSupported(t *testing.T) {
	var n atomic.Int32
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) { n.Add(1) })
	c, _ := newTestClient(t, srv, func(o *Options) { o.Environment.UnlockURL = "" })
	err := c.doJSON(t.Context(), "Unlock", "POST", unlockBase, "/v1/access-point", map[string]string{}, nil)
	if !errors.Is(err, ErrNotSupported) || n.Load() != 0 {
		t.Errorf("err=%v requests=%d", err, n.Load())
	}
	var e *Error
	if !errors.As(err, &e) || e.Op != "Unlock" {
		t.Errorf("error = %#v", err)
	}
}

func TestDoForm(t *testing.T) {
	var ct, body string
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		ct = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		_, _ = w.Write([]byte(`{"id":"9"}`))
	})
	c, _ := newTestClient(t, srv, nil)
	var out struct {
		ID string `json:"id"`
	}
	if err := c.doForm(t.Context(), "Dev", "POST", "/mobile/v4/users/devices", url.Values{"a": {"b c"}}, &out); err != nil {
		t.Fatal(err)
	}
	if ct != "application/x-www-form-urlencoded; charset=utf-8" || body != "a=b+c" || out.ID != "9" {
		t.Errorf("ct=%q body=%q out=%+v", ct, body, out)
	}
}

func TestOKStatusOverride(t *testing.T) {
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotModified) })
	c, _ := newTestClient(t, srv, nil)
	status, _, _, err := c.do(t.Context(), call{Op: "T", Method: "GET", Path: "/v3/x", OKStatus: []int{200, 304}})
	if err != nil || status != 304 {
		t.Errorf("status=%d err=%v", status, err)
	}
	if _, _, _, err := c.do(t.Context(), call{Op: "T", Method: "GET", Path: "/v3/x"}); err == nil {
		t.Error("304 should be an error by default")
	}
}

func TestLogsNeverContainSecrets(t *testing.T) {
	const token = "SECRET-TOKEN-VALUE-123"
	var calls atomic.Int32
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"x":1},"errors":[{"message":"oops"}]}`))
	})
	var logs bytes.Buffer
	c, _ := newTestClient(t, srv, func(o *Options) {
		o.Auth = StaticAPIToken(token)
		o.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	if err := c.graphQL(t.Context(), "Q", graphql.CurrentUser, map[string]any{"pin": "654321"}, nil); err != nil {
		t.Fatal(err)
	}
	err := c.doJSON(t.Context(), "J", "GET", apiBase, "/v3/x?pw=hunter2", map[string]string{"pin": "654321"}, nil)
	_ = err
	out := logs.String()
	if out == "" {
		t.Fatal("expected debug logs")
	}
	for _, s := range []string{token, "Bearer", "654321", "hunter2", "Authorization"} {
		if strings.Contains(out, s) {
			t.Errorf("log contains %q:\n%s", s, out)
		}
	}
	for _, s := range []string{"method=POST", "path=/denizen/v1/graphql", "status=503", "attempt=2", "duration="} {
		if !strings.Contains(out, s) {
			t.Errorf("log missing %q:\n%s", s, out)
		}
	}
}

func TestErrorDoesNotLeakQueryOrToken(t *testing.T) {
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) { panic(http.ErrAbortHandler) })
	c, _ := newTestClient(t, srv, func(o *Options) { o.Retry.MaxAttempts = 1 })
	err := c.doJSON(t.Context(), "T", "GET", apiBase, "/v3/x", nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if s := err.Error(); strings.Contains(s, "https://") || strings.Contains(s, "tok") {
		t.Errorf("error leaks: %s", s)
	}
}

func TestJSONAPIRealValidationBodies(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []APIErrorObject
	}{
		{"end before start",
			`{"errors":[{"source":{"pointer":"/data/attributes/starts_at"},"detail":"Start time must be before the end time"},{"source":{"pointer":"/data/attributes/ends_at"},"detail":"End time must be after the start time"}]}`,
			[]APIErrorObject{
				{Detail: "Start time must be before the end time", Source: &APIErrorSource{Pointer: "/data/attributes/starts_at"}},
				{Detail: "End time must be after the start time", Source: &APIErrorSource{Pointer: "/data/attributes/ends_at"}},
			}},
		{"too long",
			`{"errors":[{"source":{"pointer":"/data/attributes/ends_at"},"detail":"cannot exceed 365 days from start date"}]}`,
			[]APIErrorObject{{Detail: "cannot exceed 365 days from start date", Source: &APIErrorSource{Pointer: "/data/attributes/ends_at"}}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(tc.body))
			})
			c, _ := newTestClient(t, srv, nil)
			_, err := c.jsonAPI(t.Context(), "CreateKeychain", "POST", "/v3/keychains/custom", nil,
				&jsonapi.ResourceObject{Type: "keychains", Attributes: map[string]any{"name": "x"}})
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("err = %v", err)
			}
			var e *Error
			if !errors.As(err, &e) || e.StatusCode != http.StatusBadRequest || len(e.APIErrors) != len(tc.want) {
				t.Fatalf("error = %+v", e)
			}
			for i, w := range tc.want {
				g := e.APIErrors[i]
				if g.Detail != w.Detail || g.Source == nil || g.Source.Pointer != w.Source.Pointer || g.Status != "" || g.Title != "" || g.Code != "" {
					t.Errorf("APIErrors[%d] = %+v, want %+v", i, g, w)
				}
			}
			wantMsg := "butterflymx: CreateKeychain: POST /v3/keychains/custom: 400: " + tc.want[0].Detail
			if e.Error() != wantMsg {
				t.Errorf("Error() = %q, want %q", e.Error(), wantMsg)
			}
		})
	}
}

func TestJSONAPIHTMLNotFound(t *testing.T) {
	page := `<!DOCTYPE html><html><head><title>The page you were looking for doesn't exist (404)</title></head><body><h1>Nope</h1></body></html>`
	srv := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(page))
	})
	c, _ := newTestClient(t, srv, nil)
	_, err := c.jsonAPI(t.Context(), "GetKeychain", "GET", "/v3/keychains/custom/1", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	var e *Error
	if !errors.As(err, &e) || e.StatusCode != http.StatusNotFound || len(e.APIErrors) != 0 {
		t.Fatalf("error = %+v", e)
	}
	msg := e.Error()
	if strings.Contains(msg, "<") || !strings.Contains(msg, "unexpected HTML response") {
		t.Errorf("Error() = %q", msg)
	}
}
