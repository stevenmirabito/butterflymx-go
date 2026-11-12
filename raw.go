package butterflymx

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/stevenmirabito/butterflymx-go/internal/graphql"
)

// GraphQL sends an arbitrary query to the denizen GraphQL endpoint and decodes
// the response's data member into dst (nil allowed). Partial errors are logged
// and ignored; a response without data returns an *Error with GraphQLErrors.
// This is an escape hatch for operations the typed API does not cover.
//
// operationName must match a named operation in query (for example
// "query Foo { … }" with operationName "Foo"); pass "" for an anonymous query
// such as "{ … }", in which case operationName is omitted from the request.
func (c *Client) GraphQL(ctx context.Context, operationName, query string, variables map[string]any, dst any) error {
	return c.graphQL(ctx, operationName, graphql.Operation{Name: operationName, Document: query}, variables, dst)
}

// REST sends a request to a path relative to the API base URL (for example
// "/v3/access_codes"). body, if non-nil, is JSON-marshaled. The response JSON
// is decoded into dst (nil allowed). GET and DELETE are retried like the typed
// API; other methods are not. This is an escape hatch for endpoints the typed
// API does not cover.
func (c *Client) REST(ctx context.Context, method, path string, query url.Values, body any, dst any) error {
	const op = "REST"
	if !strings.HasPrefix(path, "/") {
		return &Error{Op: op, Method: method, URL: path, Err: fmt.Errorf("path %q must start with \"/\"", path)}
	}
	cl := call{Op: op, Method: method, Base: apiBase, Path: path, Query: query, Idempotent: idempotentMethod(method)}
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return &Error{Op: op, Method: method, URL: path, Err: fmt.Errorf("encode request: %w", err)}
		}
		cl.Body, cl.ContentType = b, contentTypeJSON
	}
	status, _, resp, err := c.do(ctx, cl)
	if err != nil {
		return err
	}
	if status == http.StatusNoContent {
		return nil
	}
	return decodeOut(op, method, path, status, resp, dst)
}
