package jsonapi

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
)

// ResourceObject is a resource for POST/PATCH request bodies. Attributes is
// marshaled with encoding/json/v2: use pointer fields without omitzero (or a
// map with nil values) to emit explicit nulls.
type ResourceObject struct {
	Type          string
	ID            string // omitted when empty
	Attributes    any    // omitted when nil
	Relationships map[string]RelationshipObject
}

// RelationshipObject is a request-side relationship: {"data": ...}.
type RelationshipObject struct {
	data jsontext.Value
}

// MarshalJSON implements json.Marshaler. The zero value marshals as data: null.
func (r RelationshipObject) MarshalJSON() ([]byte, error) {
	d := r.data
	if len(d) == 0 {
		d = jsontext.Value("null")
	}
	return append(append([]byte(`{"data":`), d...), '}'), nil
}

type identJSON struct {
	Type string  `json:"type"`
	ID   *string `json:"id"`
}

func rel(v any) RelationshipObject {
	b, err := json.Marshal(v)
	if err != nil { // cannot happen for these shapes
		panic(fmt.Sprintf("jsonapi: marshal relationship: %v", err))
	}
	return RelationshipObject{data: b}
}

// ToOne links a single resource.
func ToOne(typ, id string) RelationshipObject { return rel(identJSON{Type: typ, ID: &id}) }

// ToOneNull emits {"type": typ, "id": null}, which the app sends on PATCH
// (e.g. for "tenant") to mean "unchanged / not specified".
func ToOneNull(typ string) RelationshipObject { return rel(identJSON{Type: typ}) }

// ToMany links zero or more resources of one type. With no ids it emits [].
func ToMany(typ string, ids ...string) RelationshipObject {
	out := make([]identJSON, len(ids))
	for i := range ids {
		out[i] = identJSON{Type: typ, ID: &ids[i]}
	}
	return rel(out)
}

// Null emits "data": null.
func Null() RelationshipObject { return RelationshipObject{data: jsontext.Value("null")} }

type resourceJSON struct {
	Type          string                        `json:"type"`
	ID            string                        `json:"id,omitzero"`
	Attributes    any                           `json:"attributes,omitzero"`
	Relationships map[string]RelationshipObject `json:"relationships,omitzero"`
}

// Marshal renders {"data": {...}}.
func Marshal(r ResourceObject) ([]byte, error) {
	return json.Marshal(struct {
		Data resourceJSON `json:"data"`
	}{resourceJSON(r)})
}
