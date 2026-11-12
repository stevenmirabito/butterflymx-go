package butterflymx

import (
	"fmt"
	"time"
)

// Schedule says when a guest pass is valid. It is a sealed interface with two
// implementations: [CustomSchedule] (one continuous window of absolute
// instants) and [RecurringSchedule] (weekdays plus a daily window between two
// dates, in the building's local time).
type Schedule interface {
	isSchedule()
}

// CustomSchedule is one continuous validity window. The instants are absolute;
// they are sent to the API as UTC RFC 3339 with seconds precision. The server
// derives the building-local date and time fields from them (spec §7.2).
//
// The API rejects passes longer than 365 days with a 400. The minimum length
// and whether a start in the past is accepted are unverified. None of these
// is checked client-side.
type CustomSchedule struct {
	StartsAt, EndsAt time.Time
}

func (CustomSchedule) isSchedule() {}

// Validate checks that both instants are set and that EndsAt is after StartsAt
// (at the one-second precision of the wire format). The error wraps
// [ErrValidation].
func (s CustomSchedule) Validate() error {
	switch {
	case s.StartsAt.IsZero():
		return restInvalid("custom schedule: StartsAt is required")
	case s.EndsAt.IsZero():
		return restInvalid("custom schedule: EndsAt is required")
	case !s.EndsAt.Truncate(time.Second).After(s.StartsAt.Truncate(time.Second)):
		return restInvalid("custom schedule: EndsAt (%s) must be after StartsAt (%s)",
			formatInstant(s.EndsAt), formatInstant(s.StartsAt))
	}
	return nil
}

// RecurringSchedule is a daily window on selected weekdays between two dates.
// Every field is in the building's local time zone ([Building.TimeZone]); the
// server converts to absolute instants (spec §7.2). The dates are inclusive
// (inferred, spec §7.4).
//
// From may be later than To, which would describe an overnight window. The
// API's behavior for that is unverified (spec §7.4), so it is not rejected
// here; the server decides.
type RecurringSchedule struct {
	Weekdays  []Weekday
	From, To  TimeOfDay
	StartDate Date
	EndDate   Date
}

func (RecurringSchedule) isSchedule() {}

// Validate checks that there is at least one valid weekday, that From and To
// are valid times of day, that both dates are real calendar dates and that
// EndDate is not before StartDate. The error wraps [ErrValidation].
func (s RecurringSchedule) Validate() error {
	if len(s.Weekdays) == 0 {
		return restInvalid("recurring schedule: at least one weekday is required")
	}
	for _, w := range s.Weekdays {
		if _, err := ParseWeekday(string(w)); err != nil {
			return restInvalid("recurring schedule: invalid weekday %q", string(w))
		}
	}
	if err := s.From.Validate(); err != nil {
		return restInvalid("recurring schedule: From: %v", err)
	}
	if err := s.To.Validate(); err != nil {
		return restInvalid("recurring schedule: To: %v", err)
	}
	for _, d := range []struct {
		name string
		v    Date
	}{{"StartDate", s.StartDate}, {"EndDate", s.EndDate}} {
		if d.v.IsZero() {
			return restInvalid("recurring schedule: %s is required", d.name)
		}
		if DateOf(d.v.In(time.UTC)) != d.v {
			return restInvalid("recurring schedule: %s %04d-%02d-%02d is not a calendar date", d.name, d.v.Year, int(d.v.Month), d.v.Day)
		}
	}
	if s.EndDate.Before(s.StartDate) {
		return restInvalid("recurring schedule: EndDate (%s) is before StartDate (%s)", s.EndDate, s.StartDate)
	}
	return nil
}

// restInvalid returns an error wrapping ErrValidation.
func restInvalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrValidation, fmt.Sprintf(format, args...))
}

// restWeekdays normalizes ws to the short wire form and drops duplicates,
// keeping the first occurrence order. The weekdays must have been validated.
func restWeekdays(ws []Weekday) []string {
	out := make([]string, 0, len(ws))
	seen := map[Weekday]bool{}
	for _, w := range ws {
		n, err := ParseWeekday(string(w))
		if err != nil || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, string(n))
	}
	return out
}

// restValidateSchedule validates s (a nil schedule is an error) and returns it
// as a value type. With skip (Options.SkipClientValidation) only the type is
// checked, which the request path depends on.
func restValidateSchedule(s Schedule, skip bool) (Schedule, error) {
	check := func(v interface{ Validate() error }) error {
		if skip {
			return nil
		}
		return v.Validate()
	}
	switch v := s.(type) {
	case CustomSchedule:
		return v, check(v)
	case *CustomSchedule:
		if v == nil {
			break
		}
		return *v, check(v)
	case RecurringSchedule:
		return v, check(v)
	case *RecurringSchedule:
		if v == nil {
			break
		}
		return *v, check(v)
	}
	return nil, restInvalid("a CustomSchedule or RecurringSchedule is required")
}

// restApplySchedule sets the schedule members of the request attributes a in
// the shape the app uses at creation: the members the kind does not use are
// explicit nulls. It returns the path segment of the kind ("custom" or
// "recurring"). s must be a validated value schedule.
func restApplySchedule(a *restKeychainWrite, s Schedule) string {
	a.StartsAt, a.EndsAt, a.StartDate, a.EndDate, a.TimeFrom, a.TimeTo, a.Weekdays = nil, nil, nil, nil, nil, nil, nil
	switch v := s.(type) {
	case CustomSchedule:
		a.Kind = restPtr(string(KindCustom))
		a.StartsAt = restPtr(formatInstant(v.StartsAt))
		a.EndsAt = restPtr(formatInstant(v.EndsAt))
		return string(KindCustom)
	case RecurringSchedule:
		a.Kind = nil // the app sends null for recurring passes
		a.Weekdays = restPtr(restWeekdays(v.Weekdays))
		a.TimeFrom = restPtr(v.From.String())
		a.TimeTo = restPtr(v.To.String())
		a.StartDate = restPtr(v.StartDate.String())
		a.EndDate = restPtr(v.EndDate.String())
		return string(KindRecurring)
	}
	return ""
}

func restPtr[T any](v T) *T { return &v }
