package butterflymx

import (
	"fmt"
	"log/slog"
)

// PIN is a door PIN code: a string of decimal digits that may have leading
// zeros (for example "012345"). Tenant PINs and virtual-key PINs are 6 digits
// in practice.
//
// PIN implements [slog.LogValuer] so that it is redacted in structured logs.
// Use [PIN.Reveal] or a plain string conversion to get the digits.
type PIN string

// Reveal returns the PIN digits.
func (p PIN) Reveal() string { return string(p) }

// Valid reports whether p is non-empty and consists only of ASCII digits.
func (p PIN) Valid() bool {
	if p == "" {
		return false
	}
	for _, r := range p {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// LogValue implements [slog.LogValuer]. It never reveals the digits.
func (p PIN) LogValue() slog.Value {
	if p == "" {
		return slog.StringValue("")
	}
	return slog.StringValue("[redacted PIN]")
}

// Format implements [fmt.Formatter] so that %v and %s print a redacted value.
// %q also prints the redacted value. Use [PIN.Reveal] to get the digits.
func (p PIN) Format(f fmt.State, verb rune) {
	s := "[redacted PIN]"
	if p == "" {
		s = ""
	}
	if verb == 'q' {
		_, _ = fmt.Fprintf(f, "%q", s)
		return
	}
	_, _ = fmt.Fprint(f, s)
}
