package butterflymx

import (
	"encoding/json/v2"
	"errors"
	"testing"
)

func TestParseGlobalID(t *testing.T) {
	tests := []struct {
		in   string
		want GlobalID
		bad  bool
	}{
		{in: "prod-access_point-70001", want: GlobalID{"prod", "access_point", 70001}},
		{in: "prod-door_relase-123", want: GlobalID{"prod", "door_relase", 123}},
		{in: "prod-cloud_based_access_controller-80001", want: GlobalID{"prod", "cloud_based_access_controller", 80001}},
		{in: "prod--1", bad: true},
		{in: "prod-tenant-", bad: true},
		{in: "prod-tenant-12a", bad: true},
		{in: "nohyphen", bad: true},
		{in: "", bad: true},
		{in: "-tenant-1", bad: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseGlobalID(tt.in)
			if tt.bad {
				if !errors.Is(err, ErrInvalidID) {
					t.Fatalf("err = %v, want ErrInvalidID", err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("got %+v, %v; want %+v", got, err, tt.want)
			}
			if got.String() != tt.in {
				t.Errorf("String = %q", got.String())
			}
			b, err := json.Marshal(got)
			if err != nil || string(b) != `"`+tt.in+`"` {
				t.Errorf("marshal = %s, %v", b, err)
			}
			var back GlobalID
			if err := json.Unmarshal(b, &back); err != nil || back != got {
				t.Errorf("unmarshal = %+v, %v", back, err)
			}
		})
	}
}

func TestGlobalIDZeroAndNew(t *testing.T) {
	var z GlobalID
	if !z.IsZero() || z.String() != "" {
		t.Error("zero value")
	}
	g := NewGlobalID("prod", TypeTenant, 5)
	if g.IsZero() || g.String() != "prod-tenant-5" {
		t.Errorf("got %v", g)
	}
}

func TestGlobalIDAs(t *testing.T) {
	g, _ := ParseGlobalID("prod-tenant-8000001")
	if n, err := g.As(TypeTenant); err != nil || n != 8000001 {
		t.Errorf("As = %v, %v", n, err)
	}
	if _, err := g.As(TypeUnit); !errors.Is(err, ErrIDType) {
		t.Errorf("err = %v, want ErrIDType", err)
	}
}

func TestIDJSON(t *testing.T) {
	tests := []struct {
		in      string
		want    ID
		wantErr bool
	}{
		{`"123"`, 123, false},
		{`123`, 123, false},
		{`null`, 0, false},
		{`"abc"`, 0, true},
		{`"-1"`, 0, true},
		{`""`, 0, true},
		{`1.5`, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			var id ID
			err := json.Unmarshal([]byte(tt.in), &id)
			if (err != nil) != tt.wantErr || id != tt.want {
				t.Errorf("got %v, %v", id, err)
			}
		})
	}
	b, err := json.Marshal(struct {
		ID ID `json:"id"`
	}{70001})
	if err != nil || string(b) != `{"id":"70001"}` {
		t.Errorf("marshal = %s, %v", b, err)
	}
	if id, err := ParseID("42"); err != nil || id.String() != "42" {
		t.Errorf("ParseID = %v, %v", id, err)
	}
	if _, err := ParseID("+4"); !errors.Is(err, ErrInvalidID) {
		t.Errorf("err = %v", err)
	}
}
