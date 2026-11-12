package butterflymx

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Global-ID type tags.
const (
	TypeTenant                     = "tenant"
	TypeAccessPoint                = "access_point"
	TypeUnit                       = "unit"
	TypeBuilding                   = "building"
	TypeUser                       = "user"
	TypeIntercom                   = "intercom"
	TypeCloudBasedAccessController = "cloud_based_access_controller"
	TypeUserDeviceApple            = "user_device_apple"
	TypeCall                       = "call"
	// TypeDoorRelease is spelled "door_relase" because that is what the
	// server emits.
	TypeDoorRelease = "door_relase"
)

var (
	// ErrInvalidID is returned when an ID string cannot be parsed.
	ErrInvalidID = errors.New("butterflymx: invalid id")
	// ErrIDType is returned when a global ID has an unexpected type tag.
	ErrIDType = errors.New("butterflymx: unexpected id type")
)

// ID is a numeric REST ID. It is a decimal string on the wire. Zero means unset.
type ID int64

// ParseID parses a decimal ID.
func ParseID(s string) (ID, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 || s[0] == '+' {
		return 0, fmt.Errorf("%w: %q", ErrInvalidID, s)
	}
	return ID(n), nil
}

// String returns the decimal form.
func (id ID) String() string { return strconv.FormatInt(int64(id), 10) }

// MarshalJSON encodes the ID as a JSON string.
func (id ID) MarshalJSON() ([]byte, error) {
	return strconv.AppendQuote(nil, id.String()), nil
}

// UnmarshalJSON accepts a JSON string or number. null is a no-op.
func (id *ID) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if string(b) == "null" {
		return nil
	}
	s := string(b)
	if len(b) > 0 && b[0] == '"' {
		u, err := strconv.Unquote(s)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrInvalidID, s)
		}
		s = u
	}
	v, err := ParseID(s)
	if err != nil {
		return err
	}
	*id = v
	return nil
}

// GlobalID is a prefixed ID such as "prod-access_point-70001".
type GlobalID struct {
	Env, Type string
	Num       ID
}

// NewGlobalID builds a GlobalID.
func NewGlobalID(env, typ string, n ID) GlobalID { return GlobalID{Env: env, Type: typ, Num: n} }

// ParseGlobalID parses "{env}-{type}-{number}". The type is not validated
// against a fixed list.
func ParseGlobalID(s string) (GlobalID, error) {
	first := strings.Index(s, "-")
	last := strings.LastIndex(s, "-")
	if first < 0 || last == first {
		return GlobalID{}, fmt.Errorf("%w: %q", ErrInvalidID, s)
	}
	env, typ, num := s[:first], s[first+1:last], s[last+1:]
	if env == "" || typ == "" || num == "" {
		return GlobalID{}, fmt.Errorf("%w: %q", ErrInvalidID, s)
	}
	for i := 0; i < len(num); i++ {
		if num[i] < '0' || num[i] > '9' {
			return GlobalID{}, fmt.Errorf("%w: %q", ErrInvalidID, s)
		}
	}
	n, err := ParseID(num)
	if err != nil {
		return GlobalID{}, fmt.Errorf("%w: %q", ErrInvalidID, s)
	}
	return GlobalID{Env: env, Type: typ, Num: n}, nil
}

// String returns the wire form, or "" for the zero value.
func (g GlobalID) String() string {
	if g.IsZero() {
		return ""
	}
	return g.Env + "-" + g.Type + "-" + g.Num.String()
}

// IsZero reports whether g is unset.
func (g GlobalID) IsZero() bool { return g == GlobalID{} }

// MarshalText implements encoding.TextMarshaler.
func (g GlobalID) MarshalText() ([]byte, error) { return []byte(g.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler. An empty string yields the zero value.
func (g *GlobalID) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*g = GlobalID{}
		return nil
	}
	v, err := ParseGlobalID(string(b))
	if err != nil {
		return err
	}
	*g = v
	return nil
}

// As returns the numeric ID if g has type tag typ, else an error wrapping ErrIDType.
func (g GlobalID) As(typ string) (ID, error) {
	if g.Type != typ {
		return 0, fmt.Errorf("%w: have %q, want %q (%s)", ErrIDType, g.Type, typ, g)
	}
	return g.Num, nil
}
