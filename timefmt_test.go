package butterflymx

import (
	"encoding/json/v2"
	"testing"
	"time"
)

func TestDate(t *testing.T) {
	tests := []struct {
		in  string
		bad bool
	}{
		{"2026-11-12", false}, {"2024-02-29", false},
		{"2026-02-30", true}, {"2026-13-01", true}, {"11/12/2026", true}, {"", true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			d, err := ParseDate(tt.in)
			if (err != nil) != tt.bad {
				t.Fatalf("err = %v", err)
			}
			if !tt.bad && d.String() != tt.in {
				t.Errorf("String = %q", d)
			}
		})
	}
	var d Date
	if err := json.Unmarshal([]byte(`"2026-11-12"`), &d); err != nil || d != (Date{2026, 11, 12}) {
		t.Errorf("unmarshal = %v, %v", d, err)
	}
	b, _ := json.Marshal(d)
	if string(b) != `"2026-11-12"` {
		t.Errorf("marshal = %s", b)
	}
}

func TestDateOps(t *testing.T) {
	a := Date{2026, 12, 31}
	if got := a.AddDays(1); got != (Date{2027, 1, 1}) {
		t.Errorf("AddDays = %v", got)
	}
	if got := a.AddDays(-31); got != (Date{2026, 11, 30}) {
		t.Errorf("AddDays = %v", got)
	}
	b := Date{2027, 1, 1}
	if !a.Before(b) || a.After(b) || !b.After(a) || a.Equal(b) || !a.Equal(a) {
		t.Error("comparison")
	}
	if !(Date{}).IsZero() || a.IsZero() {
		t.Error("IsZero")
	}
	la, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		la = time.FixedZone("PST", -8*3600)
	}
	tm := time.Date(2026, 11, 11, 23, 30, 0, 0, la)
	if got := DateOf(tm); got != (Date{2026, 11, 11}) {
		t.Errorf("DateOf = %v", got)
	}
	if got := (Date{2026, 11, 11}).In(la); !got.Equal(time.Date(2026, 11, 11, 0, 0, 0, 0, la)) {
		t.Errorf("In = %v", got)
	}
}

func TestTimeOfDay(t *testing.T) {
	tests := []struct {
		in  string
		bad bool
	}{
		{"09:00", false}, {"23:59", false}, {"00:00", false},
		{"24:00", true}, {"12:60", true}, {"9:00pm", true}, {"", true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			v, err := ParseTimeOfDay(tt.in)
			if (err != nil) != tt.bad {
				t.Fatalf("err = %v", err)
			}
			if !tt.bad && v.String() != tt.in {
				t.Errorf("String = %q", v)
			}
		})
	}
	if err := (TimeOfDay{24, 0}).Validate(); err == nil {
		t.Error("want error")
	}
	if err := (TimeOfDay{-1, 0}).Validate(); err == nil {
		t.Error("want error")
	}
	if _, err := json.Marshal(TimeOfDay{25, 0}); err == nil {
		t.Error("marshal invalid should fail")
	}
	var v TimeOfDay
	if err := json.Unmarshal([]byte(`"17:05"`), &v); err != nil || v != (TimeOfDay{17, 5}) {
		t.Errorf("unmarshal = %v, %v", v, err)
	}
	la := time.FixedZone("PST", -8*3600)
	got := TimeOfDay{9, 0}.On(Date{2026, 11, 11}, la)
	if formatInstant(got) != "2026-11-11T17:00:00Z" {
		t.Errorf("On = %s", formatInstant(got))
	}
}

func TestWeekday(t *testing.T) {
	tests := []struct {
		in   string
		want Weekday
		bad  bool
	}{
		{"MONDAY", Monday, false}, {"mon", Monday, false}, {"Mon", Monday, false},
		{"Sunday", Sunday, false}, {"sat", Saturday, false}, {" Fri ", Friday, false},
		{"mo", "", true}, {"", "", true}, {"funday", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseWeekday(tt.in)
			if (err != nil) != tt.bad || got != tt.want {
				t.Errorf("got %q, %v", got, err)
			}
		})
	}
	for d := time.Sunday; d <= time.Saturday; d++ {
		w := WeekdayOf(d)
		if !w.Valid() || w.TimeWeekday() != d {
			t.Errorf("round trip %v -> %q", d, w)
		}
	}
	if Weekday("xyz").Valid() || WeekdayOf(time.Weekday(9)) != "" {
		t.Error("invalid")
	}
	b, err := json.Marshal([]Weekday{Monday, "WEDNESDAY"})
	if err != nil || string(b) != `["mon","wed"]` {
		t.Errorf("marshal = %s, %v", b, err)
	}
	var ws []Weekday
	if err := json.Unmarshal([]byte(`["TUESDAY","thu"]`), &ws); err != nil || len(ws) != 2 || ws[0] != Tuesday || ws[1] != Thursday {
		t.Errorf("unmarshal = %v, %v", ws, err)
	}
}

func TestInstant(t *testing.T) {
	pst := time.FixedZone("", -8*3600)
	if got := formatInstant(time.Date(2026, 11, 11, 21, 0, 0, 999, pst)); got != "2026-11-12T05:00:00Z" {
		t.Errorf("formatInstant = %q", got)
	}
	want := time.Date(2026, 11, 12, 5, 0, 0, 0, time.UTC)
	for _, in := range []string{"2026-11-12T05:00:00Z", "2026-11-11T21:00:00-08:00", "2026-11-11T21:00:00-0800"} {
		got, err := parseInstant(in)
		if err != nil || !got.Equal(want) {
			t.Errorf("parseInstant(%q) = %v, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "2026-11-12", "yesterday"} {
		if _, err := parseInstant(in); err == nil {
			t.Errorf("parseInstant(%q): want error", in)
		}
	}
}

func TestNullableTime(t *testing.T) {
	var v struct {
		SentAt nullableTime `json:"sent_at"`
		SeenAt nullableTime `json:"seen_at"`
	}
	if err := json.Unmarshal([]byte(`{"sent_at":null,"seen_at":"2026-11-11T21:00:00-0800"}`), &v); err != nil {
		t.Fatal(err)
	}
	if v.SentAt.T != nil {
		t.Error("sent_at should be nil")
	}
	if v.SeenAt.T == nil || !v.SeenAt.T.Equal(time.Date(2026, 11, 12, 5, 0, 0, 0, time.UTC)) {
		t.Errorf("seen_at = %v", v.SeenAt.T)
	}
	if err := json.Unmarshal([]byte(`{"sent_at":"nope"}`), &v); err == nil {
		t.Error("want error")
	}
	b, err := json.Marshal(v.SeenAt)
	if err != nil || string(b) != `"2026-11-12T05:00:00Z"` {
		t.Errorf("marshal = %s, %v", b, err)
	}
	b, _ = json.Marshal(nullableTime{})
	if string(b) != "null" {
		t.Errorf("marshal nil = %s", b)
	}
}
