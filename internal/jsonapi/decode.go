package jsonapi

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
)

// Identifier is a resource linkage object. IDs are numeric strings, and the
// same ID may occur under different types.
type Identifier struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Resource is a decoded resource object.
type Resource struct {
	Identifier
	Attributes    jsontext.Value          `json:"attributes,omitzero"`
	Relationships map[string]Relationship `json:"relationships,omitzero"`
}

// DecodeAttributes decodes the attributes into v, ignoring unknown fields.
// A resource without attributes leaves v untouched.
func (r Resource) DecodeAttributes(v any) error {
	if len(r.Attributes) == 0 || string(r.Attributes) == "null" {
		return nil
	}
	return json.Unmarshal(r.Attributes, v)
}

// Relationship holds the raw "data" member of a relationship, which is
// null, a single identifier or an array of identifiers (possibly of mixed
// types). Data is empty when the member was absent.
type Relationship struct {
	Data jsontext.Value `json:"data,omitzero"`
}

// One returns the single linked identifier, or nil for null or absent data.
func (r Relationship) One() (*Identifier, error) {
	if isNull(r.Data) {
		return nil, nil
	}
	if r.Data.Kind() != '{' {
		return nil, fmt.Errorf("jsonapi: relationship data is not an object: %.40s", r.Data)
	}
	var id Identifier
	if err := json.Unmarshal(r.Data, &id); err != nil {
		return nil, fmt.Errorf("jsonapi: decode identifier: %w", err)
	}
	return &id, nil
}

// Many returns the linked identifiers. Null, absent and [] yield an empty
// slice. A single object is returned as a one-element slice.
func (r Relationship) Many() ([]Identifier, error) {
	if isNull(r.Data) {
		return nil, nil
	}
	switch r.Data.Kind() {
	case '{':
		id, err := r.One()
		if err != nil {
			return nil, err
		}
		return []Identifier{*id}, nil
	case '[':
		var ids []Identifier
		if err := json.Unmarshal(r.Data, &ids); err != nil {
			return nil, fmt.Errorf("jsonapi: decode identifiers: %w", err)
		}
		return ids, nil
	}
	return nil, fmt.Errorf("jsonapi: relationship data is neither array nor object: %.40s", r.Data)
}

func isNull(v jsontext.Value) bool {
	return len(v) == 0 || string(v) == "null"
}

// Links are the pagination links. Absent or null links are "".
type Links struct {
	Self, First, Prev, Next, Last string
}

// UnmarshalJSON accepts string links, null, and link objects with "href".
func (l *Links) UnmarshalJSON(b []byte) error {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	get := func(k string) string { return linkString(raw[k]) }
	*l = Links{Self: get("self"), First: get("first"), Prev: get("prev"), Next: get("next"), Last: get("last")}
	return nil
}

func linkString(v jsontext.Value) string {
	switch v.Kind() {
	case '"':
		var s string
		_ = json.Unmarshal(v, &s)
		return s
	case '{':
		var o struct {
			Href string `json:"href"`
		}
		_ = json.Unmarshal(v, &o)
		return o.Href
	}
	return ""
}

// HasNext reports whether another page follows.
func HasNext(l Links) bool { return l.Next != "" }

// ErrorSource locates the cause of an error.
type ErrorSource struct {
	Pointer   string `json:"pointer,omitzero"`
	Parameter string `json:"parameter,omitzero"`
}

// ErrorObject is a JSON:API error object. Status and Code are strings even
// if the server sent numbers.
type ErrorObject struct {
	Status string
	Code   string
	Title  string
	Detail string
	Source *ErrorSource
}

// UnmarshalJSON decodes leniently: scalar members of any type are
// stringified, and malformed members are dropped rather than failing.
func (e *ErrorObject) UnmarshalJSON(b []byte) error {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*e = ErrorObject{
		Status: scalarString(raw["status"]),
		Code:   scalarString(raw["code"]),
		Title:  scalarString(raw["title"]),
		Detail: scalarString(raw["detail"]),
	}
	if s, ok := raw["source"]; ok && s.Kind() == '{' {
		var src map[string]jsontext.Value
		if json.Unmarshal(s, &src) == nil {
			e.Source = &ErrorSource{Pointer: scalarString(src["pointer"]), Parameter: scalarString(src["parameter"])}
		}
	}
	return nil
}

func scalarString(v jsontext.Value) string {
	switch v.Kind() {
	case '"':
		var s string
		_ = json.Unmarshal(v, &s)
		return s
	case '0', 't', 'f':
		return string(v)
	}
	return ""
}

func (e ErrorObject) Error() string {
	s := e.Status
	if e.Title != "" {
		s += " " + e.Title
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return "jsonapi: " + s
}

// Document is a decoded top-level JSON:API document.
type Document struct {
	Data     jsontext.Value `json:"data,omitzero"`
	Included []Resource     `json:"included,omitzero"`
	Links    Links          `json:"links,omitzero"`
	Errors   []ErrorObject  `json:"errors,omitzero"`
}

// Decode parses a JSON:API document. Unknown members are ignored.
func Decode(body []byte) (*Document, error) {
	var d Document
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("jsonapi: decode document: %w", err)
	}
	return &d, nil
}

// One returns the primary data as a single resource.
func (d *Document) One() (Resource, error) {
	if d.Data.Kind() != '{' {
		return Resource{}, errors.New("jsonapi: primary data is not a single resource object")
	}
	var r Resource
	if err := json.Unmarshal(d.Data, &r); err != nil {
		return Resource{}, fmt.Errorf("jsonapi: decode resource: %w", err)
	}
	return r, nil
}

// Many returns the primary data as a list of resources.
func (d *Document) Many() ([]Resource, error) {
	if d.Data.Kind() != '[' {
		return nil, errors.New("jsonapi: primary data is not an array")
	}
	var rs []Resource
	if err := json.Unmarshal(d.Data, &rs); err != nil {
		return nil, fmt.Errorf("jsonapi: decode resources: %w", err)
	}
	return rs, nil
}

// Index maps (type, id) to resources.
type Index struct {
	m map[Identifier]Resource
}

// Index builds a lookup over the primary data and included resources.
// Malformed primary data is skipped. Primary data wins over included on
// duplicates.
func (d *Document) Index() *Index {
	x := &Index{m: make(map[Identifier]Resource, len(d.Included)+1)}
	for _, r := range d.Included {
		x.m[r.Identifier] = r
	}
	switch d.Data.Kind() {
	case '{':
		if r, err := d.One(); err == nil {
			x.m[r.Identifier] = r
		}
	case '[':
		if rs, err := d.Many(); err == nil {
			for _, r := range rs {
				x.m[r.Identifier] = r
			}
		}
	}
	return x
}

// Get looks up a resource by (type, id).
func (x *Index) Get(id Identifier) (Resource, bool) {
	r, ok := x.m[id]
	return r, ok
}

// Resolve returns the resources a relationship points to, in order, plus
// the identifiers that were not present in the document (soft misses).
func (x *Index) Resolve(rel Relationship) ([]Resource, []Identifier, error) {
	ids, err := rel.Many()
	if err != nil {
		return nil, nil, err
	}
	var found []Resource
	var missing []Identifier
	for _, id := range ids {
		if r, ok := x.m[id]; ok {
			found = append(found, r)
		} else {
			missing = append(missing, id)
		}
	}
	return found, missing, nil
}
