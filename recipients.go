package butterflymx

import (
	"errors"
	"strings"
)

// Recipient is a guest who receives a virtual key. ButterflyMX delivers the
// key by email or SMS, choosing the channel from DeliverTo (spec §7.5): an
// email address means email, a phone number means SMS. Delivery cannot be
// suppressed.
//
// Build recipients with [EmailRecipient] or [SMSRecipient].
type Recipient struct {
	Name      string // the guest's name; required
	DeliverTo string // an email address or an E.164 phone number
}

// EmailRecipient returns a recipient that receives the key by email.
func EmailRecipient(name, email string) Recipient {
	return Recipient{Name: strings.TrimSpace(name), DeliverTo: strings.TrimSpace(email)}
}

// SMSRecipient returns a recipient that receives the key by SMS. phone is
// normalized to E.164: spaces, dots, dashes and parentheses are removed, ten
// digits get the +1 country code, eleven digits starting with 1 get a +, and a
// leading + is kept. A number that cannot be normalized (for example one with
// letters, or a non-+ number of another length) is stored as given, so that
// [Recipient.Validate] reports it.
func SMSRecipient(name, phone string) Recipient {
	return Recipient{Name: strings.TrimSpace(name), DeliverTo: restE164(phone)}
}

func restE164(phone string) string {
	s := strings.TrimSpace(phone)
	plus := strings.HasPrefix(s, "+")
	var digits strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits.WriteRune(r)
		case strings.ContainsRune(" ()-.+\t", r):
		default:
			return s
		}
	}
	d := digits.String()
	switch {
	case plus && d != "":
		return "+" + d
	case len(d) == 10:
		return "+1" + d
	case len(d) == 11 && d[0] == '1':
		return "+" + d
	}
	return s
}

// Validate checks that Name is set and that DeliverTo is either an email
// address (a single @, a non-empty local part and a domain containing a dot)
// or an E.164 number (+ followed by 8 to 15 digits). The error wraps
// [ErrValidation].
func (r Recipient) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return restInvalid("recipient: name is required")
	}
	d := r.DeliverTo
	switch {
	case d == "":
		return restInvalid("recipient %q: deliver_to is required", r.Name)
	case strings.Contains(d, "@"):
		if !restEmailOK(d) {
			return restInvalid("recipient %q: %q is not an email address", r.Name, d)
		}
	case !restE164OK(d):
		return restInvalid("recipient %q: %q is neither an email address nor an E.164 phone number", r.Name, d)
	}
	return nil
}

func restEmailOK(s string) bool {
	if strings.Count(s, "@") != 1 || strings.ContainsAny(s, " \t\r\n,;<>") {
		return false
	}
	local, domain, _ := strings.Cut(s, "@")
	return local != "" && strings.Contains(domain, ".") &&
		!strings.HasPrefix(domain, ".") && !strings.HasSuffix(domain, ".")
}

func restE164OK(s string) bool {
	if len(s) < 9 || len(s) > 16 || s[0] != '+' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// restRecipient is the wire form of a Recipient.
type restRecipient struct {
	Name      string `json:"name"`
	DeliverTo string `json:"deliver_to"`
}

// restRecipients validates rs and converts them to the wire form. The result
// is never nil, so it encodes as [] when empty. With skip
// (Options.SkipClientValidation) nothing is validated and the fields are sent
// as given.
func restRecipients(rs []Recipient, skip bool) ([]restRecipient, error) {
	out := make([]restRecipient, 0, len(rs))
	var errs []error
	for _, r := range rs {
		if skip {
			out = append(out, restRecipient(r))
			continue
		}
		if err := r.Validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, restRecipient{Name: strings.TrimSpace(r.Name), DeliverTo: r.DeliverTo})
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}
