package butterflymx

import (
	"errors"
	"testing"
)

func TestRESTSMSRecipientNormalization(t *testing.T) {
	tests := map[string]string{
		"(555) 555-0100":    "+15555550100",
		"555-555-0100":      "+15555550100",
		"555.555.0100":      "+15555550100",
		"5555550100":        "+15555550100",
		" 15555550100 ":     "+15555550100",
		"1 (555) 555-0100":  "+15555550100",
		"+1 555 555 0100":   "+15555550100",
		"+44 20 7946 0958":  "+442079460958",
		"+15555550100":      "+15555550100",
		"+(1) 555-555-0100": "+15555550100",
	}
	for in, want := range tests {
		if got := SMSRecipient("Alex", in); got.DeliverTo != want || got.Name != "Alex" {
			t.Errorf("SMSRecipient(%q).DeliverTo = %q, want %q", in, got.DeliverTo, want)
		}
		if err := SMSRecipient("Alex", in).Validate(); err != nil {
			t.Errorf("SMSRecipient(%q) does not validate: %v", in, err)
		}
	}
	// Not normalizable: kept as given, and rejected by Validate.
	for _, in := range []string{"", "555-0100", "call me", "25555550100", "123456789012"} {
		r := SMSRecipient("Alex", in)
		if r.DeliverTo != in {
			t.Errorf("SMSRecipient(%q).DeliverTo = %q, want unchanged", in, r.DeliverTo)
		}
		if err := r.Validate(); !errors.Is(err, ErrValidation) {
			t.Errorf("SMSRecipient(%q).Validate() = %v, want ErrValidation", in, err)
		}
	}
}

func TestRESTRecipientValidate(t *testing.T) {
	tests := []struct {
		name string
		r    Recipient
		ok   bool
	}{
		{"email", EmailRecipient("A", "a@example.com"), true},
		{"email with plus and subdomain", EmailRecipient("A", "a+b@mail.example.co.uk"), true},
		{"email is trimmed", EmailRecipient("A", "  a@example.com "), true},
		{"e164", Recipient{"A", "+15555550100"}, true},
		{"e164 shortest", Recipient{"A", "+12345678"}, true},
		{"e164 longest", Recipient{"A", "+123456789012345"}, true},
		{"no name", Recipient{"", "a@example.com"}, false},
		{"blank name", Recipient{"  ", "a@example.com"}, false},
		{"no deliver_to", Recipient{"A", ""}, false},
		{"two @", Recipient{"A", "a@b@example.com"}, false},
		{"no local part", Recipient{"A", "@example.com"}, false},
		{"no dot in domain", Recipient{"A", "a@localhost"}, false},
		{"dot at end of domain", Recipient{"A", "a@example."}, false},
		{"dot at start of domain", Recipient{"A", "a@.com"}, false},
		{"space in email", Recipient{"A", "a b@example.com"}, false},
		{"e164 too short", Recipient{"A", "+1234567"}, false},
		{"e164 too long", Recipient{"A", "+1234567890123456"}, false},
		{"unformatted phone", Recipient{"A", "(555) 555-0100"}, false},
		{"no plus", Recipient{"A", "15555550100"}, false},
		{"letters", Recipient{"A", "+1555CALLME"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.r.Validate()
			if (err == nil) != tt.ok {
				t.Fatalf("Validate() = %v, want ok=%v", err, tt.ok)
			}
			if err != nil && !errors.Is(err, ErrValidation) {
				t.Errorf("error does not wrap ErrValidation: %v", err)
			}
		})
	}
}

func TestRESTRecipientsWire(t *testing.T) {
	out, err := restRecipients(nil, false)
	if err != nil || out == nil || len(out) != 0 {
		t.Errorf("restRecipients(nil, false) = %#v, %v; want a non-nil empty slice", out, err)
	}
	_, err = restRecipients([]Recipient{EmailRecipient("A", "a@example.com"), {Name: "", DeliverTo: "x"}, EmailRecipient("B", "bad")}, false)
	if !errors.Is(err, ErrValidation) {
		t.Errorf("err = %v", err)
	}
}
