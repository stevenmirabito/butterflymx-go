package butterflymx

import (
	"errors"
	"testing"
	"time"
)

func TestRESTCustomScheduleValidate(t *testing.T) {
	a := time.Date(2026, 11, 12, 5, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		s    CustomSchedule
		ok   bool
	}{
		{"valid", CustomSchedule{a, a.Add(time.Hour)}, true},
		{"valid across zones", CustomSchedule{a, a.Add(time.Hour).In(time.FixedZone("x", -8*3600))}, true},
		{"start in the past is allowed", CustomSchedule{time.Unix(1, 0), time.Unix(100, 0)}, true},
		{"zero start", CustomSchedule{EndsAt: a}, false},
		{"zero end", CustomSchedule{StartsAt: a}, false},
		{"end equals start", CustomSchedule{a, a}, false},
		{"end before start", CustomSchedule{a, a.Add(-time.Minute)}, false},
		{"same second", CustomSchedule{a, a.Add(900 * time.Millisecond)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.s.Validate()
			if (err == nil) != tt.ok {
				t.Fatalf("Validate() = %v, want ok=%v", err, tt.ok)
			}
			if err != nil && !errors.Is(err, ErrValidation) {
				t.Errorf("error does not wrap ErrValidation: %v", err)
			}
		})
	}
}

func TestRESTRecurringScheduleValidate(t *testing.T) {
	good := func() RecurringSchedule {
		return RecurringSchedule{
			Weekdays: []Weekday{Monday, Friday}, From: TimeOfDay{9, 0}, To: TimeOfDay{17, 0},
			StartDate: Date{2026, 11, 11}, EndDate: Date{2026, 11, 30},
		}
	}
	tests := []struct {
		name string
		mod  func(*RecurringSchedule)
		ok   bool
	}{
		{"valid", func(*RecurringSchedule) {}, true},
		{"same day", func(s *RecurringSchedule) { s.EndDate = s.StartDate }, true},
		{"long names accepted", func(s *RecurringSchedule) { s.Weekdays = []Weekday{"Monday"} }, true},
		{"overnight window is not rejected", func(s *RecurringSchedule) { s.From, s.To = TimeOfDay{22, 0}, TimeOfDay{6, 0} }, true},
		{"equal times are not rejected", func(s *RecurringSchedule) { s.To = s.From }, true},
		{"no weekdays", func(s *RecurringSchedule) { s.Weekdays = nil }, false},
		{"invalid weekday", func(s *RecurringSchedule) { s.Weekdays = []Weekday{Monday, "funday"} }, false},
		{"bad hour", func(s *RecurringSchedule) { s.From = TimeOfDay{24, 0} }, false},
		{"bad minute", func(s *RecurringSchedule) { s.To = TimeOfDay{1, 60} }, false},
		{"zero start date", func(s *RecurringSchedule) { s.StartDate = Date{} }, false},
		{"zero end date", func(s *RecurringSchedule) { s.EndDate = Date{} }, false},
		{"end before start", func(s *RecurringSchedule) { s.EndDate = Date{2026, 11, 10} }, false},
		{"not a calendar date", func(s *RecurringSchedule) { s.EndDate = Date{2026, 2, 30} }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := good()
			tt.mod(&s)
			err := s.Validate()
			if (err == nil) != tt.ok {
				t.Fatalf("Validate() = %v, want ok=%v", err, tt.ok)
			}
			if err != nil && !errors.Is(err, ErrValidation) {
				t.Errorf("error does not wrap ErrValidation: %v", err)
			}
		})
	}
}

func TestRESTKeychainScheduleView(t *testing.T) {
	a := time.Date(2026, 11, 12, 5, 0, 0, 0, time.UTC)
	b := a.Add(time.Hour)
	k := Keychain{Kind: KindCustom, StartsAt: a, EndsAt: b}
	if s, ok := k.Schedule().(CustomSchedule); !ok || !s.StartsAt.Equal(a) || !s.EndsAt.Equal(b) {
		t.Errorf("custom Schedule() = %#v", k.Schedule())
	}
	k.Kind = KindDeliveryPass
	if _, ok := k.Schedule().(CustomSchedule); !ok {
		t.Errorf("delivery pass Schedule() = %#v", k.Schedule())
	}
	k = Keychain{Kind: KindRecurring, Weekdays: []Weekday{Monday}, TimeFrom: TimeOfDay{9, 0}, TimeTo: TimeOfDay{17, 0},
		StartDate: Date{2026, 11, 11}, EndDate: Date{2026, 11, 30}}
	rs, ok := k.Schedule().(RecurringSchedule)
	if !ok || rs.From != k.TimeFrom || rs.To != k.TimeTo || rs.StartDate != k.StartDate || rs.EndDate != k.EndDate || len(rs.Weekdays) != 1 {
		t.Errorf("recurring Schedule() = %#v", k.Schedule())
	}
	// A schedule taken from a keychain is valid input again.
	if err := rs.Validate(); err != nil {
		t.Error(err)
	}
	if (Keychain{Kind: "other"}).Schedule() != nil {
		t.Error("unknown kind should have no schedule")
	}
}

func TestRESTValidateScheduleForms(t *testing.T) {
	a := time.Date(2026, 11, 12, 5, 0, 0, 0, time.UTC)
	cs := CustomSchedule{a, a.Add(time.Hour)}
	if s, err := restValidateSchedule(&cs, false); err != nil || s != (CustomSchedule{a, a.Add(time.Hour)}) {
		t.Errorf("pointer form: %v %v", s, err)
	}
	var nilPtr *CustomSchedule
	if _, err := restValidateSchedule(nilPtr, false); !errors.Is(err, ErrValidation) {
		t.Errorf("nil pointer: %v", err)
	}
	if _, err := restValidateSchedule(nil, false); !errors.Is(err, ErrValidation) {
		t.Errorf("nil: %v", err)
	}
}
