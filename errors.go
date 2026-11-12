package butterflymx

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Sentinels usable with errors.Is.
var (
	ErrUnauthorized = errors.New("butterflymx: unauthorized")      // 401
	ErrForbidden    = errors.New("butterflymx: forbidden")         // 403
	ErrNotFound     = errors.New("butterflymx: not found")         // 404
	ErrConflict     = errors.New("butterflymx: conflict")          // 409
	ErrValidation   = errors.New("butterflymx: validation failed") // 400, 422
	ErrRateLimited  = errors.New("butterflymx: rate limited")      // 429
	ErrServer       = errors.New("butterflymx: server error")      // 5xx
	// ErrNotSupported marks an endpoint that is unverified or unsupported in this environment.
	ErrNotSupported = errors.New("butterflymx: not supported")
	// ErrUnknownRegion is returned (wrapped) for a region other than "na" or
	// "eu", by [EnvironmentForRegion] and by [New] for [Options.Region].
	ErrUnknownRegion = errors.New("butterflymx: unknown region")
)

// APIErrorObject is a JSON:API error object.
type APIErrorObject struct {
	Status string          `json:"status,omitempty"`
	Code   string          `json:"code,omitempty"`
	Title  string          `json:"title,omitempty"`
	Detail string          `json:"detail,omitempty"`
	Source *APIErrorSource `json:"source,omitempty"`
}

// APIErrorSource locates the cause of a JSON:API error.
type APIErrorSource struct {
	Pointer   string `json:"pointer,omitempty"`
	Parameter string `json:"parameter,omitempty"`
}

// GraphQLError is one entry of a GraphQL response's errors array.
type GraphQLError struct {
	Message    string         `json:"message"`
	Path       []any          `json:"path,omitempty"`
	Extensions map[string]any `json:"extensions,omitempty"`
}

// Error is returned for any failed API operation.
type Error struct {
	Op     string // library operation, e.g. "CreateKeychain"
	Method string
	URL    string // never contains secrets; callers strip query strings on the accounts host

	StatusCode    int // 0 for transport errors and for GraphQL errors on HTTP 200
	APIErrors     []APIErrorObject
	GraphQLErrors []GraphQLError
	Body          []byte // first <= 2 KiB of the raw response body
	Err           error  // underlying cause, may be nil
}

// Error implements error.
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("butterflymx:")
	if e.Op != "" {
		b.WriteString(" " + e.Op + ":")
	}
	if e.Method != "" || e.URL != "" {
		b.WriteString(" " + strings.TrimSpace(e.Method+" "+displayURL(e.URL)) + ":")
	}
	if e.StatusCode != 0 {
		b.WriteString(" " + strconv.Itoa(e.StatusCode) + ":")
	}
	if m := e.message(); m != "" {
		b.WriteString(" " + m)
	}
	s := b.String()
	return strings.TrimSuffix(s, ":")
}

func displayURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return raw
	}
	return u.Path
}

func (e *Error) message() string {
	for _, a := range e.APIErrors {
		switch {
		case a.Detail != "":
			return a.Detail
		case a.Title != "":
			return a.Title
		case a.Source != nil && a.Source.Pointer != "":
			return a.Source.Pointer
		}
	}
	for _, g := range e.GraphQLErrors {
		if g.Message != "" {
			return g.Message
		}
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	if looksLikeHTML(e.Body) {
		return "unexpected HTML response"
	}
	return ""
}

func looksLikeHTML(b []byte) bool {
	s := strings.ToLower(strings.TrimSpace(string(b[:min(len(b), 256)])))
	return strings.HasPrefix(s, "<!doctype html") || strings.HasPrefix(s, "<html") || strings.Contains(s, "<html")
}

// Unwrap returns the underlying cause.
func (e *Error) Unwrap() error { return e.Err }

// Is maps StatusCode to the package sentinels.
func (e *Error) Is(target error) bool {
	switch target {
	case ErrUnauthorized:
		return e.StatusCode == http.StatusUnauthorized
	case ErrForbidden:
		return e.StatusCode == http.StatusForbidden
	case ErrNotFound:
		return e.StatusCode == http.StatusNotFound
	case ErrConflict:
		return e.StatusCode == http.StatusConflict
	case ErrValidation:
		// The /v3 validation errors are 400; 422 is kept because
		// other endpoints may still use the conventional Rails status.
		return e.StatusCode == http.StatusBadRequest || e.StatusCode == http.StatusUnprocessableEntity
	case ErrRateLimited:
		return e.StatusCode == http.StatusTooManyRequests
	case ErrServer:
		return e.StatusCode >= 500 && e.StatusCode <= 599
	}
	return false
}
