package butterflymx

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"strings"
	"time"
)

// Date is a calendar date without a zone (wire format 2006-01-02). The zone is
// supplied by context, typically the building's time zone.
type Date struct {
	Year  int
	Month time.Month
	Day   int
}

// ParseDate parses "2006-01-02".
func ParseDate(s string) (Date, error) {
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		return Date{}, fmt.Errorf("butterflymx: invalid date %q: %w", s, err)
	}
	return DateOf(t), nil
}

// DateOf returns the date of t in t's location.
func DateOf(t time.Time) Date {
	y, m, d := t.Date()
	return Date{y, m, d}
}

// IsZero reports whether d is unset.
func (d Date) IsZero() bool { return d == Date{} }

// String returns the wire form, or "" for the zero value.
func (d Date) String() string {
	if d.IsZero() {
		return ""
	}
	return fmt.Sprintf("%04d-%02d-%02d", d.Year, int(d.Month), d.Day)
}

// In returns midnight of d in loc.
func (d Date) In(loc *time.Location) time.Time {
	return time.Date(d.Year, d.Month, d.Day, 0, 0, 0, 0, loc)
}

func (d Date) key() int { return (d.Year*100+int(d.Month))*100 + d.Day }

// Before reports whether d is earlier than o.
func (d Date) Before(o Date) bool { return d.key() < o.key() }

// After reports whether d is later than o.
func (d Date) After(o Date) bool { return d.key() > o.key() }

// Equal reports whether d and o are the same date.
func (d Date) Equal(o Date) bool { return d == o }

// AddDays returns the date n days later (n may be negative).
func (d Date) AddDays(n int) Date {
	return DateOf(time.Date(d.Year, d.Month, d.Day+n, 0, 0, 0, 0, time.UTC))
}

// MarshalText implements encoding.TextMarshaler.
func (d Date) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler. An empty string yields the zero value.
func (d *Date) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*d = Date{}
		return nil
	}
	v, err := ParseDate(string(b))
	if err != nil {
		return err
	}
	*d = v
	return nil
}

// TimeOfDay is a wall-clock time (wire format 15:04).
type TimeOfDay struct {
	Hour, Minute int
}

// ParseTimeOfDay parses "15:04".
func ParseTimeOfDay(s string) (TimeOfDay, error) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return TimeOfDay{}, fmt.Errorf("butterflymx: invalid time of day %q: %w", s, err)
	}
	return TimeOfDay{t.Hour(), t.Minute()}, nil
}

// Validate checks Hour is 0-23 and Minute is 0-59.
func (t TimeOfDay) Validate() error {
	if t.Hour < 0 || t.Hour > 23 || t.Minute < 0 || t.Minute > 59 {
		return fmt.Errorf("butterflymx: invalid time of day %02d:%02d", t.Hour, t.Minute)
	}
	return nil
}

// String returns "HH:MM".
func (t TimeOfDay) String() string { return fmt.Sprintf("%02d:%02d", t.Hour, t.Minute) }

// On returns the instant at which t occurs on date d in loc.
func (t TimeOfDay) On(d Date, loc *time.Location) time.Time {
	return time.Date(d.Year, d.Month, d.Day, t.Hour, t.Minute, 0, 0, loc)
}

// MarshalText implements encoding.TextMarshaler. It fails if t is invalid.
func (t TimeOfDay) MarshalText() ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return []byte(t.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (t *TimeOfDay) UnmarshalText(b []byte) error {
	v, err := ParseTimeOfDay(string(b))
	if err != nil {
		return err
	}
	*t = v
	return nil
}

// Weekday is a day of the week in the API's short lowercase form.
type Weekday string

// Weekdays as sent on the wire.
const (
	Monday    Weekday = "mon"
	Tuesday   Weekday = "tue"
	Wednesday Weekday = "wed"
	Thursday  Weekday = "thu"
	Friday    Weekday = "fri"
	Saturday  Weekday = "sat"
	Sunday    Weekday = "sun"
)

var weekdayOrder = [...]Weekday{Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday}

// ParseWeekday accepts "mon", "MONDAY", "Monday" etc. and returns the short form.
func ParseWeekday(s string) (Weekday, error) {
	l := strings.ToLower(strings.TrimSpace(s))
	for _, w := range weekdayOrder {
		if l == string(w) || l == strings.ToLower(w.TimeWeekday().String()) {
			return w, nil
		}
	}
	return "", fmt.Errorf("butterflymx: invalid weekday %q", s)
}

// WeekdayOf converts a time.Weekday.
func WeekdayOf(d time.Weekday) Weekday {
	if d < time.Sunday || d > time.Saturday {
		return ""
	}
	return weekdayOrder[d]
}

// Valid reports whether w is one of the seven canonical values.
func (w Weekday) Valid() bool {
	for _, x := range weekdayOrder {
		if w == x {
			return true
		}
	}
	return false
}

// TimeWeekday converts to time.Weekday. Invalid values return time.Sunday; check Valid first.
func (w Weekday) TimeWeekday() time.Weekday {
	for i, x := range weekdayOrder {
		if w == x {
			return time.Weekday(i)
		}
	}
	return time.Sunday
}

// MarshalText implements encoding.TextMarshaler, normalizing to the short form.
func (w Weekday) MarshalText() ([]byte, error) {
	v, err := ParseWeekday(string(w))
	if err != nil {
		return nil, err
	}
	return []byte(v), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (w *Weekday) UnmarshalText(b []byte) error {
	v, err := ParseWeekday(string(b))
	if err != nil {
		return err
	}
	*w = v
	return nil
}

// formatInstant renders t as UTC RFC 3339 with seconds precision.
func formatInstant(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// parseInstant accepts RFC 3339 (with Z or a colon offset) and the
// numeric-offset form 2006-01-02T15:04:05-0700.
func parseInstant(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02T15:04:05-0700", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("butterflymx: invalid timestamp %q", s)
}

// nullableTime decodes a JSON string instant or null (T == nil).
type nullableTime struct{ T *time.Time }

func (n *nullableTime) UnmarshalJSON(b []byte) error {
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		n.T = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	t, err := parseInstant(s)
	if err != nil {
		return err
	}
	n.T = &t
	return nil
}

func (n nullableTime) MarshalJSON() ([]byte, error) {
	if n.T == nil {
		return []byte("null"), nil
	}
	return json.Marshal(formatInstant(*n.T))
}
