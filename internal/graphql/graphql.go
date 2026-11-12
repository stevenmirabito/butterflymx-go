// Package graphql contains the GraphQL envelope types, Relay pagination
// helpers and the query documents used by the ButterflyMX resident API.
package graphql

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"iter"
	"strings"
)

// MaxPages caps the number of pages Pages will fetch.
const MaxPages = 1000

// Request is the body of a GraphQL POST.
type Request struct {
	OperationName string         `json:"operationName,omitzero"` // omitted when empty (anonymous operation)
	Query         string         `json:"query"`
	Variables     map[string]any `json:"variables,omitempty"`
	Extensions    map[string]any `json:"extensions,omitzero"`
}

// NewRequest builds a Request for op with the app's client extensions.
func NewRequest(op Operation, vars map[string]any) Request {
	return Request{OperationName: op.Name, Query: op.Document, Variables: vars, Extensions: Extensions()}
}

// Location is a source position in a GraphQL error.
type Location struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// Error is a single GraphQL error.
type Error struct {
	Message    string         `json:"message"`
	Path       []any          `json:"path,omitempty"`
	Extensions map[string]any `json:"extensions,omitempty"`
	Locations  []Location     `json:"locations,omitempty"`
}

// Error implements the error interface.
func (e Error) Error() string { return e.Message }

// Errors is a list of GraphQL errors and implements error.
type Errors []Error

// Error joins the messages.
func (e Errors) Error() string {
	msgs := make([]string, len(e))
	for i, x := range e {
		msgs[i] = x.Message
	}
	return "graphql: " + strings.Join(msgs, "; ")
}

// Response is the GraphQL response envelope.
type Response struct {
	Data   jsontext.Value `json:"data"`
	Errors Errors         `json:"errors,omitempty"`
}

// Decode parses a response body. If data is null or absent, the returned err
// is the Errors (or a generic error if there are none). Otherwise data is
// decoded into dst and any errors are returned as partial.
func Decode(body []byte, dst any) (partial Errors, err error) {
	var r Response
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("graphql: decode response: %w", err)
	}
	if len(r.Data) == 0 || string(r.Data) == "null" {
		if len(r.Errors) > 0 {
			return nil, r.Errors
		}
		return nil, errors.New("graphql: response has no data")
	}
	if dst != nil {
		if err := json.Unmarshal(r.Data, dst); err != nil {
			return r.Errors, fmt.Errorf("graphql: decode data: %w", err)
		}
	}
	return r.Errors, nil
}

// PageInfo is the Relay page info.
type PageInfo struct {
	HasNextPage bool   `json:"hasNextPage"`
	EndCursor   string `json:"endCursor"`
}

// Connection is a Relay connection of nodes.
type Connection[T any] struct {
	PageInfo PageInfo `json:"pageInfo"`
	Nodes    []T      `json:"nodes"`
}

// Pages iterates over all items of a paginated query. The first call to
// fetch receives after == "". It stops after the last page, and yields an
// error (then stops) on a fetch error, a repeated cursor, a missing cursor
// when more pages are claimed, exceeding MaxPages, or ctx cancellation.
func Pages[T any](ctx context.Context, fetch func(ctx context.Context, after string) ([]T, PageInfo, error)) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		var zero T
		after := ""
		seen := map[string]bool{}
		for page := 0; ; page++ {
			if err := ctx.Err(); err != nil {
				yield(zero, err)
				return
			}
			if page >= MaxPages {
				yield(zero, fmt.Errorf("graphql: pagination exceeded %d pages", MaxPages))
				return
			}
			nodes, info, err := fetch(ctx, after)
			if err != nil {
				yield(zero, err)
				return
			}
			for _, n := range nodes {
				if !yield(n, nil) {
					return
				}
			}
			if !info.HasNextPage {
				return
			}
			if info.EndCursor == "" || seen[info.EndCursor] || info.EndCursor == after {
				yield(zero, fmt.Errorf("graphql: repeated or empty pagination cursor %q", info.EndCursor))
				return
			}
			seen[info.EndCursor] = true
			after = info.EndCursor
		}
	}
}
