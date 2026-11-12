package butterflymx

// Internal request pipeline (read this before writing endpoint code).
//
// Every endpoint method of Client goes through one of four helpers, which all
// funnel into Client.do:
//
//	type call struct {
//	    Op, Method string; Base baseURL; Path string; Query url.Values
//	    Body []byte; ContentType string; Header http.Header
//	    Idempotent bool; OKStatus []int
//	}
//	func (c *Client) do(ctx, cl call) (status int, header http.Header, body []byte, err error)
//
//	// GraphQL: POST {APIURL}/denizen/v1/graphql with x-bmx-service and the Apollo
//	// extensions. Always idempotent. Decodes "data" into dst (nil allowed).
//	// Partial errors are logged at Warn and the data is returned; data:null plus
//	// errors yields *Error with GraphQLErrors.
//	func (c *Client) graphQL(ctx, op string, gop graphql.Operation, vars map[string]any, dst any) error
//
//	// REST /v3 JSON:API. body may be nil. Returns nil document for 204 or an
//	// empty body. Idempotent for GET and DELETE only.
//	func (c *Client) jsonAPI(ctx, op, method, path string, query url.Values, body *jsonapi.ResourceObject) (*jsonapi.Document, error)
//
//	// Plain JSON (unlock service etc.). in and out may be nil. base is apiBase or
//	// unlockBase. Idempotent for GET and DELETE only.
//	func (c *Client) doJSON(ctx, op, method string, base baseURL, path string, in, out any) error
//
//	// application/x-www-form-urlencoded; charset=utf-8 (/mobile/v4). out may be nil.
//	func (c *Client) doForm(ctx, op, method, path string, form url.Values, out any) error
//
// Pipeline guarantees of do:
//   - Authorization comes from Options.Auth. A 401 invalidates the token that
//     was used and retries exactly once (every method). A second 401 returns an
//     *Error satisfying errors.Is(err, ErrUnauthorized).
//   - Network errors, 5xx and 429 are retried (with full-jitter backoff,
//     Retry-After honored, ctx honored) only when call.Idempotent is set.
//     A DELETE answered 404 after a retried attempt is treated as success: do
//     returns status 404, nil body and a nil error.
//   - Any other status outside call.OKStatus (default 200, 201, 204) becomes an
//     *Error with Op, Method, URL (path only), StatusCode, APIErrors and Body.
//   - Bodies are []byte, so they are safe to resend. Response bodies are always
//     closed. Logs (Debug) contain method, path, status, duration and attempt,
//     and never tokens, headers, query values or bodies.
//   - An unlockBase call in an environment with an empty UnlockURL fails with an
//     *Error wrapping ErrNotSupported before any request is made.

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/stevenmirabito/butterflymx-go/internal/graphql"
	"github.com/stevenmirabito/butterflymx-go/internal/jsonapi"
)

type baseURL int

const (
	apiBase    baseURL = iota // Environment.APIURL
	unlockBase                // Environment.UnlockURL
)

const (
	contentTypeJSON = "application/json"
	contentTypeForm = "application/x-www-form-urlencoded; charset=utf-8"

	graphQLPath = "/denizen/v1/graphql"

	maxErrorRead   = 64 << 10
	maxErrorBody   = 2 << 10
	maxResponse    = 32 << 20
	maxRetryAfter  = 60 * time.Second
	acceptLanguage = "en-US;q=1.0"
)

type call struct {
	Op          string      // library operation name, for errors and logs
	Method      string      // HTTP method
	Base        baseURL     // apiBase or unlockBase
	Path        string      // path relative to the base, starting with "/"
	Query       url.Values  // may be nil
	Body        []byte      // already encoded; nil for none
	ContentType string      // set when Body is non-empty
	Header      http.Header // extra headers; override the defaults
	Idempotent  bool        // whether retries on network error, 5xx and 429 are allowed
	OKStatus    []int       // accepted statuses; default 200, 201, 204
}

// idempotentMethod is the default retry policy by method.
func idempotentMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodDelete
}

func (c *Client) notSupported(cl call) error {
	return &Error{Op: cl.Op, Method: cl.Method, URL: cl.Path,
		Err: fmt.Errorf("%w: no unlock service URL for environment %q", ErrNotSupported, c.env.Name)}
}

func (c *Client) buildURL(cl call) (*url.URL, error) {
	base := c.env.APIURL
	if cl.Base == unlockBase {
		base = c.env.UnlockURL
	}
	u, err := url.Parse(strings.TrimRight(base, "/") + cl.Path)
	if err != nil {
		return nil, err
	}
	if len(cl.Query) > 0 {
		u.RawQuery = cl.Query.Encode()
	}
	return u, nil
}

func (c *Client) do(ctx context.Context, cl call) (int, http.Header, []byte, error) {
	if cl.Base == unlockBase && c.env.UnlockURL == "" {
		return 0, nil, nil, c.notSupported(cl)
	}
	u, err := c.buildURL(cl)
	if err != nil {
		return 0, nil, nil, &Error{Op: cl.Op, Method: cl.Method, URL: cl.Path, Err: fmt.Errorf("build url: %w", err)}
	}
	ok := cl.OKStatus
	if len(ok) == 0 {
		ok = []int{http.StatusOK, http.StatusCreated, http.StatusNoContent}
	}
	fail := func(status int, body []byte, cause error) error {
		e := &Error{Op: cl.Op, Method: cl.Method, URL: u.Path, StatusCode: status, Err: cause}
		if status != 0 {
			e.Body = body[:min(len(body), maxErrorBody)]
			e.APIErrors = parseAPIErrors(body)
		}
		return e
	}

	token, err := c.tokenFor(ctx)
	if err != nil {
		return 0, nil, nil, fail(0, nil, err)
	}
	var (
		attempt   int
		reauthed  bool
		retried   bool
		maxTries  = c.retry.MaxAttempts
		backoffNo int
	)
	for {
		attempt++
		start := time.Now()
		status, hdr, body, nerr := c.send(ctx, cl, u, token, ok)
		c.log.LogAttrs(ctx, slog.LevelDebug, "butterflymx request",
			slog.String("op", cl.Op), slog.String("method", cl.Method), slog.String("path", u.Path),
			slog.Int("status", status), slog.Duration("duration", time.Since(start)), slog.Int("attempt", attempt))

		var retryAfter time.Duration
		switch {
		case nerr != nil:
			if ctx.Err() != nil {
				return 0, nil, nil, fail(0, nil, ctx.Err())
			}
			if !cl.Idempotent || attempt >= maxTries {
				return 0, nil, nil, fail(0, nil, nerr)
			}
		case slices.Contains(ok, status):
			return status, hdr, body, nil
		case status == http.StatusUnauthorized:
			if reauthed {
				return status, hdr, body, fail(status, body, nil)
			}
			reauthed = true
			if err := c.cfg.Auth.InvalidateAPIToken(ctx, token); err != nil {
				return status, hdr, body, fail(status, body, fmt.Errorf("invalidate token: %w", err))
			}
			if token, err = c.tokenFor(ctx); err != nil {
				return status, hdr, body, fail(status, body, err)
			}
			continue
		case cl.Method == http.MethodDelete && status == http.StatusNotFound && retried:
			return status, hdr, nil, nil
		case (status >= 500 || status == http.StatusTooManyRequests) && cl.Idempotent && attempt < maxTries:
			retryAfter = parseRetryAfter(hdr.Get("Retry-After"))
		default:
			return status, hdr, body, fail(status, body, nil)
		}

		backoffNo++
		d := c.backoff(backoffNo, retryAfter)
		if err := c.sleep(ctx, d); err != nil {
			return 0, nil, nil, fail(0, nil, err)
		}
		retried = true
	}
}

func (c *Client) tokenFor(ctx context.Context) (string, error) {
	tok, err := c.cfg.Auth.APIToken(ctx)
	if err != nil {
		return "", fmt.Errorf("get api token: %w", err)
	}
	if tok == "" {
		return "", errors.New("get api token: empty token")
	}
	return tok, nil
}

// send performs a single HTTP exchange. A non-nil error means a transport
// failure. Non-OK bodies are truncated to maxErrorRead.
func (c *Client) send(ctx context.Context, cl call, u *url.URL, token string, ok []int) (int, http.Header, []byte, error) {
	var rdr io.Reader
	if len(cl.Body) > 0 {
		rdr = bytes.NewReader(cl.Body)
	}
	req, err := http.NewRequestWithContext(ctx, cl.Method, u.String(), rdr)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", acceptLanguage)
	if len(cl.Body) > 0 && cl.ContentType != "" {
		req.Header.Set("Content-Type", cl.ContentType)
	}
	for k, vs := range cl.Header {
		req.Header[http.CanonicalHeaderKey(k)] = slices.Clone(vs)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, redactURLError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	limit := int64(maxResponse)
	if !slices.Contains(ok, resp.StatusCode) {
		limit = maxErrorRead
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return 0, nil, nil, redactURLError(err)
	}
	return resp.StatusCode, resp.Header, body, nil
}

// redactURLError strips the URL (which carries query values) from *url.Error.
func redactURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

func parseAPIErrors(body []byte) []APIErrorObject {
	if len(body) == 0 || body[0] != '{' {
		return nil
	}
	doc, err := jsonapi.Decode(body)
	if err != nil || len(doc.Errors) == 0 {
		return nil
	}
	out := make([]APIErrorObject, len(doc.Errors))
	for i, e := range doc.Errors {
		out[i] = APIErrorObject{Status: e.Status, Code: e.Code, Title: e.Title, Detail: e.Detail}
		if e.Source != nil {
			out[i].Source = &APIErrorSource{Pointer: e.Source.Pointer, Parameter: e.Source.Parameter}
		}
	}
	return out
}

func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	var d time.Duration
	if n, err := strconv.Atoi(v); err == nil {
		d = time.Duration(max(n, 0)) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = max(time.Until(t), 0)
	}
	return min(d, maxRetryAfter)
}

// backoff returns the delay before retry number n (1-based): full jitter over
// min(MaxDelay, BaseDelay*2^(n-1)), or the server's Retry-After if larger.
func (c *Client) backoff(n int, retryAfter time.Duration) time.Duration {
	ceil := c.retry.BaseDelay
	for i := 1; i < n && ceil < c.retry.MaxDelay; i++ {
		ceil *= 2
	}
	ceil = min(ceil, c.retry.MaxDelay)
	var d time.Duration
	if ceil > 0 {
		d = rand.N(ceil + 1)
	}
	return max(d, retryAfter)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *Client) graphQL(ctx context.Context, op string, gop graphql.Operation, vars map[string]any, dst any) error {
	body, err := json.Marshal(graphql.NewRequest(gop, vars))
	if err != nil {
		return &Error{Op: op, Method: http.MethodPost, URL: graphQLPath, Err: fmt.Errorf("encode request: %w", err)}
	}
	_, _, resp, err := c.do(ctx, call{
		Op: op, Method: http.MethodPost, Base: apiBase, Path: graphQLPath,
		Body: body, ContentType: contentTypeJSON,
		Header:     http.Header{"Accept": {contentTypeJSON}, "X-Bmx-Service": {"denizen-api"}},
		Idempotent: true,
	})
	if err != nil {
		return err
	}
	partial, err := graphql.Decode(resp, dst)
	if err != nil {
		e := &Error{Op: op, Method: http.MethodPost, URL: graphQLPath, Err: err}
		var ge graphql.Errors
		if errors.As(err, &ge) {
			e.Err = nil
			e.GraphQLErrors = convertGraphQLErrors(ge)
		}
		if len(partial) > 0 {
			e.GraphQLErrors = convertGraphQLErrors(partial)
		}
		e.Body = resp[:min(len(resp), maxErrorBody)]
		return e
	}
	if len(partial) > 0 {
		c.log.LogAttrs(ctx, slog.LevelWarn, "butterflymx graphql partial errors",
			slog.String("op", op), slog.Int("errors", len(partial)))
	}
	return nil
}

func convertGraphQLErrors(in graphql.Errors) []GraphQLError {
	out := make([]GraphQLError, len(in))
	for i, e := range in {
		out[i] = GraphQLError{Message: e.Message, Path: e.Path, Extensions: e.Extensions}
	}
	return out
}

func (c *Client) jsonAPI(ctx context.Context, op, method, path string, query url.Values, body *jsonapi.ResourceObject) (*jsonapi.Document, error) {
	cl := call{Op: op, Method: method, Base: apiBase, Path: path, Query: query, Idempotent: idempotentMethod(method)}
	if body != nil {
		b, err := jsonapi.Marshal(*body)
		if err != nil {
			return nil, &Error{Op: op, Method: method, URL: path, Err: fmt.Errorf("encode request: %w", err)}
		}
		cl.Body, cl.ContentType = b, contentTypeJSON
	}
	status, _, resp, err := c.do(ctx, cl)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNoContent || len(bytes.TrimSpace(resp)) == 0 {
		return nil, nil
	}
	doc, err := jsonapi.Decode(resp)
	if err != nil {
		return nil, &Error{Op: op, Method: method, URL: path, StatusCode: status, Err: err}
	}
	return doc, nil
}

func (c *Client) doJSON(ctx context.Context, op, method string, base baseURL, path string, in, out any) error {
	cl := call{Op: op, Method: method, Base: base, Path: path, Idempotent: idempotentMethod(method)}
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return &Error{Op: op, Method: method, URL: path, Err: fmt.Errorf("encode request: %w", err)}
		}
		cl.Body, cl.ContentType = b, contentTypeJSON
	}
	status, _, resp, err := c.do(ctx, cl)
	if err != nil {
		return err
	}
	return decodeOut(op, method, path, status, resp, out)
}

func (c *Client) doForm(ctx context.Context, op, method, path string, form url.Values, out any) error {
	cl := call{Op: op, Method: method, Base: apiBase, Path: path, Idempotent: idempotentMethod(method)}
	if form != nil {
		cl.Body, cl.ContentType = []byte(form.Encode()), contentTypeForm
	}
	status, _, resp, err := c.do(ctx, cl)
	if err != nil {
		return err
	}
	return decodeOut(op, method, path, status, resp, out)
}

func decodeOut(op, method, path string, status int, resp []byte, out any) error {
	if out == nil || status == http.StatusNoContent || len(bytes.TrimSpace(resp)) == 0 {
		return nil
	}
	if err := json.Unmarshal(resp, out); err != nil {
		return &Error{Op: op, Method: method, URL: path, StatusCode: status, Err: fmt.Errorf("decode response: %w", err)}
	}
	return nil
}
