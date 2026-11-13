package auth

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"
)

func start(t *testing.T, f *fake, opts ...LoginOption) *MFAChallenge {
	t.Helper()
	res, err := StartLogin(context.Background(), f.cfg(), testEmail, testPassword, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if res.Token != nil || res.Challenge == nil {
		t.Fatalf("want challenge, got %+v", res)
	}
	return res.Challenge
}

func roundTrip(t *testing.T, c *MFAChallenge) *MFAChallenge {
	t.Helper()
	data, err := c.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var c2 MFAChallenge
	if err := c2.UnmarshalBinary(data); err != nil {
		t.Fatal(err)
	}
	return &c2
}

func complete(t *testing.T, f *fake, c *MFAChallenge) {
	t.Helper()
	tok, err := CompleteLogin(context.Background(), f.cfg(), c, testCode)
	if err != nil {
		t.Fatal(err)
	}
	if tok.APIToken != "FAKE_API_TOKEN" {
		t.Errorf("token = %v", tok)
	}
}

func wantLog(t *testing.T, f *fake, want ...string) {
	t.Helper()
	if got := f.log(); !slices.Equal(got, want) {
		t.Errorf("requests:\n got %q\nwant %q", got, want)
	}
}

func TestSMSLoginWrongCodeResendSuccess(t *testing.T) {
	f := newFake(t)
	f.defaultMFA = "sms"
	ctx := context.Background()
	c := start(t, f)
	if c.Method != MFASMS || c.Destination != "******0100" || !c.CanResend() {
		t.Fatalf("challenge = %v", c)
	}
	wantLog(t, f, "GET new type=sms")

	// Wrong code: the challenge is refreshed in place from the re-rendered page.
	oldVerify, oldResend := c.csrf, c.resendToken
	if _, err := CompleteLogin(ctx, f.cfg(), c, "000000"); !errors.Is(err, ErrInvalidMFACode) {
		t.Fatalf("err = %v", err)
	}
	f.mu.Lock()
	page := f.csrf
	f.mu.Unlock()
	if c.csrf == oldVerify || c.csrf != page {
		t.Error("verify token not refreshed from the re-rendered page")
	}
	if c.resendToken == oldResend || c.resendToken != page {
		t.Error("resend token not refreshed from the re-rendered page")
	}
	if c.Destination != "******0100" || c.Method != MFASMS {
		t.Errorf("challenge = %v", c)
	}

	// Resend through a marshaled copy: context=resend with the resend form's
	// token and no X-CSRF-Token (the fake rejects one); the challenge picks up
	// the new page's tokens.
	c = roundTrip(t, c)
	staleResend := c.resendToken
	if err := ResendMFACode(ctx, f.cfg(), c); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	raw := f.lastResend
	page = f.csrf
	f.mu.Unlock()
	if want := "_csrf_token=" + staleResend + "&context=resend"; raw != want {
		t.Errorf("resend body = %q, want %q", raw, want)
	}
	if c.csrf != page || c.resendToken != page || c.resendToken == staleResend {
		t.Error("challenge not refreshed after resend")
	}

	// The verify POST uses the resend page's fresh tokens (the fake checks them).
	complete(t, f, c)
	wantLog(t, f, "GET new type=sms", "POST verify type=sms", "POST resend type=sms", "POST verify type=sms")
}

func TestEmailResendAndLogin(t *testing.T) {
	f := newFake(t)
	f.defaultMFA = "email"
	c := start(t, f)
	if c.Method != MFAEmail || c.Destination != "" || !c.CanResend() {
		t.Fatalf("challenge = %v", c)
	}
	if err := ResendMFACode(context.Background(), f.cfg(), c); err != nil {
		t.Fatal(err)
	}
	complete(t, f, roundTrip(t, c))
	wantLog(t, f, "GET new type=email", "POST resend type=email", "POST verify type=email")
}

func TestSwitchMFAMethod(t *testing.T) {
	tests := []struct {
		to      MFAMethod
		dest    string
		resend  bool
		wantLog []string
	}{
		{MFAEmail, "", true, []string{"GET new type=authenticator_app", "GET picker", "GET choose type=email", "POST verify type=email"}},
		{MFASMS, "******0100", true, []string{"GET new type=authenticator_app", "GET picker", "GET choose type=sms", "POST verify type=sms"}},
		{MFAAuthenticatorApp, "", false, []string{"GET new type=authenticator_app", "GET picker", "GET choose type=authenticator_app", "POST verify type=authenticator_app"}},
	}
	for _, tt := range tests {
		t.Run(string(tt.to), func(t *testing.T) {
			f := newFake(t)
			c := start(t, f)
			if c.Method != MFAAuthenticatorApp || c.CanResend() {
				t.Fatalf("challenge = %v", c)
			}
			if err := SwitchMFAMethod(context.Background(), f.cfg(), c, tt.to); err != nil {
				t.Fatal(err)
			}
			if c.Method != tt.to || c.Destination != tt.dest || c.CanResend() != tt.resend || c.mfaType != string(tt.to) {
				t.Errorf("challenge = %v (type %q, resend %v)", c, c.mfaType, c.CanResend())
			}
			complete(t, f, roundTrip(t, c))
			wantLog(t, f, tt.wantLog...)
		})
	}
}

func TestSwitchToCurrentMethodResends(t *testing.T) {
	f := newFake(t)
	f.defaultMFA = "sms"
	c := start(t, f)
	if err := SwitchMFAMethod(context.Background(), f.cfg(), c, MFASMS); err != nil {
		t.Fatal(err)
	}
	complete(t, f, c)
	wantLog(t, f, "GET new type=sms", "GET picker", "GET choose type=sms", "POST verify type=sms")
}

func TestWithMFAMethodShortcut(t *testing.T) {
	f := newFake(t)
	f.defaultMFA = "sms"
	c := start(t, f, WithMFAMethod(MFAEmail))
	if c.Method != MFAEmail || c.Destination != "" {
		t.Fatalf("challenge = %v", c)
	}
	// The default page is never requested, so it cannot send a text.
	wantLog(t, f, "GET picker", "GET choose type=email")
	complete(t, f, c)
}

func TestWithMFAMethodFallback(t *testing.T) {
	t.Run("redirect once", func(t *testing.T) {
		f := newFake(t)
		f.defaultMFA = "sms"
		f.pickerMode = "redirect-once"
		c := start(t, f, WithMFAMethod(MFAEmail))
		if c.Method != MFAEmail {
			t.Fatalf("challenge = %v", c)
		}
		wantLog(t, f, "GET picker", "GET new type=sms", "GET picker", "GET choose type=email")
		complete(t, f, c)
	})
	for _, mode := range []string{"redirect", "garbage"} {
		t.Run(mode+" always", func(t *testing.T) {
			f := newFake(t)
			f.defaultMFA = "sms"
			f.pickerMode = mode
			_, err := StartLogin(context.Background(), f.cfg(), testEmail, testPassword, WithMFAMethod(MFAEmail))
			if !errors.Is(err, ErrLoginFlowChanged) {
				t.Fatalf("err = %v", err)
			}
			wantLog(t, f, "GET picker", "GET new type=sms", "GET picker")
		})
	}
}

func TestWithMFAMethodEqualToDefault(t *testing.T) {
	f := newFake(t)
	f.defaultMFA = "sms"
	c := start(t, f, WithMFAMethod(MFASMS))
	if c.Method != MFASMS || c.Destination != "******0100" {
		t.Fatalf("challenge = %v", c)
	}
	wantLog(t, f, "GET new type=sms")
	complete(t, f, c)
}

func TestWithMFAMethodUnknown(t *testing.T) {
	f := newFake(t)
	_, err := StartLogin(context.Background(), f.cfg(), testEmail, testPassword, WithMFAMethod("carrier-pigeon"))
	if !errors.Is(err, ErrMFAMethodUnsupported) {
		t.Fatalf("err = %v", err)
	}
	if f.requests.Load() != 0 {
		t.Error("an unknown method must fail before any request")
	}
}

func TestUnknownDefaultMethod(t *testing.T) {
	f := newFake(t)
	f.defaultMFA = "carrier-pigeon"
	_, err := StartLogin(context.Background(), f.cfg(), testEmail, testPassword)
	if !errors.Is(err, ErrMFAMethodUnsupported) {
		t.Fatalf("err = %v", err)
	}
	wantLog(t, f) // the challenge page was never requested
}

func TestResendUnsupportedForAuthenticatorApp(t *testing.T) {
	f := newFake(t)
	c := start(t, f)
	before := f.requests.Load()
	if err := ResendMFACode(context.Background(), f.cfg(), c); !errors.Is(err, ErrMFAResendUnsupported) {
		t.Fatalf("err = %v", err)
	}
	if f.requests.Load() != before {
		t.Error("no request expected")
	}
	if err := SwitchMFAMethod(context.Background(), f.cfg(), c, "carrier-pigeon"); !errors.Is(err, ErrMFAMethodUnsupported) {
		t.Fatalf("err = %v", err)
	}
	if f.requests.Load() != before {
		t.Error("no request expected")
	}
}

func TestSwitchResendExpired(t *testing.T) {
	f := newFake(t)
	f.defaultMFA = "sms"
	c := start(t, f)
	before := f.requests.Load()
	c.CreatedAt = time.Now().Add(-11 * time.Minute)
	if err := ResendMFACode(context.Background(), f.cfg(), c); !errors.Is(err, ErrMFAExpired) {
		t.Fatalf("err = %v", err)
	}
	if err := SwitchMFAMethod(context.Background(), f.cfg(), c, MFAEmail); !errors.Is(err, ErrMFAExpired) {
		t.Fatalf("err = %v", err)
	}
	if f.requests.Load() != before {
		t.Error("no request expected")
	}
}

func TestPickerWithoutLinkIsMethodUnsupported(t *testing.T) {
	f := newFake(t)
	f.pickerMode = "no-sms"
	c := start(t, f)
	before := *c
	err := SwitchMFAMethod(context.Background(), f.cfg(), c, MFASMS)
	if !errors.Is(err, ErrMFAMethodUnsupported) || errors.Is(err, ErrLoginFlowChanged) {
		t.Fatalf("err = %v", err)
	}
	f.mu.Lock()
	page := f.csrf
	f.mu.Unlock()
	if c.Method != before.Method || c.mfaType != before.mfaType || c.action != before.action || c.resendAction != before.resendAction {
		t.Error("challenge changed by a failed switch")
	}
	// The failed request rotated the CSRF cookie; the form tokens follow it.
	if c.csrf != page || (before.resendToken != "" && c.resendToken != page) {
		t.Error("form tokens do not match the server's current token after a failed switch")
	}
	// Other methods are still there.
	if err := SwitchMFAMethod(context.Background(), f.cfg(), c, MFAEmail); err != nil {
		t.Fatal(err)
	}
}

func TestWithMFAMethodPickerWithoutLinkFailsFast(t *testing.T) {
	f := newFake(t)
	f.pickerMode = "no-sms"
	_, err := StartLogin(context.Background(), f.cfg(), testEmail, testPassword, WithMFAMethod(MFASMS))
	if !errors.Is(err, ErrMFAMethodUnsupported) {
		t.Fatalf("err = %v", err)
	}
	// A recognized picker without the method is a real answer, not a reason to fall back.
	wantLog(t, f, "GET picker")
}

func TestChallengeMarshalMidFlow(t *testing.T) {
	for _, m := range []string{"sms", "email"} {
		t.Run(m, func(t *testing.T) {
			f := newFake(t)
			f.defaultMFA = m
			c := start(t, f)
			c2 := roundTrip(t, c)
			if c2.Method != c.Method || c2.Destination != c.Destination || !c2.CreatedAt.Equal(c.CreatedAt) ||
				c2.csrf != c.csrf || c2.mfaType != c.mfaType ||
				c2.resendAction != c.resendAction || c2.resendToken != c.resendToken ||
				c2.verifier != c.verifier || c2.state != c.state || c2.resendToken == "" ||
				!strings.HasSuffix(c2.resendAction, "/new?type="+m) || c2.resendFields["context"] != "resend" {
				t.Errorf("round trip lost data: %v vs %v", c2, c)
			}
			complete(t, f, c2)
		})
	}
}

func TestChallengeBlobVersion(t *testing.T) {
	f := newFake(t)
	c := start(t, f)
	data, err := c.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"version":3`) {
		t.Errorf("blob = %s", data)
	}
	// Challenges from before the accounts rewrite hold dead sessions: reject.
	var w challengeWire
	if err := json.Unmarshal(data, &w); err != nil {
		t.Fatal(err)
	}
	for _, v := range []int{1, 2} {
		w.Version = v
		old, err := json.Marshal(w)
		if err != nil {
			t.Fatal(err)
		}
		var c2 MFAChallenge
		if err := c2.UnmarshalBinary(old); err == nil {
			t.Errorf("version %d blob accepted", v)
		}
	}
}

func TestResendWithoutResendFormReselects(t *testing.T) {
	f := newFake(t)
	f.defaultMFA = "sms"
	c := start(t, f)
	c.resendAction, c.resendToken, c.resendFields = "", "", nil
	if err := ResendMFACode(context.Background(), f.cfg(), c); err != nil {
		t.Fatal(err)
	}
	if c.resendToken == "" {
		t.Error("resend form not learned")
	}
	wantLog(t, f, "GET new type=sms", "GET picker", "GET choose type=sms")
}

func TestChallengeDoesNotPrintSecrets(t *testing.T) {
	f := newFake(t)
	f.defaultMFA = "sms"
	c := start(t, f)
	secrets := []string{c.csrf, c.resendToken, c.verifier, c.state, c.cookies[0].Value}
	var sb strings.Builder
	slog.New(slog.NewTextHandler(&sb, nil)).Info("challenge", "c", c, "v", *c)
	for _, out := range []string{
		c.String(), fmt.Sprint(c), fmt.Sprint(*c), fmt.Sprintf("%v %+v %#v %s", c, c, c, c), fmt.Sprintf("%+v %#v", *c, *c), sb.String(),
	} {
		for _, s := range secrets {
			if s == "" || strings.Contains(out, s) {
				t.Errorf("%q leaks or secret empty (%q)", out, s)
			}
		}
		if !strings.Contains(out, "sms") {
			t.Errorf("%q lacks the method", out)
		}
	}
	if !strings.Contains(c.String(), "******0100") {
		t.Errorf("String() = %q", c.String())
	}
}

func TestParseMFAMethod(t *testing.T) {
	tests := []struct {
		in   string
		want MFAMethod
		ok   bool
	}{
		{"app", MFAAuthenticatorApp, true},
		{"authenticator", MFAAuthenticatorApp, true},
		{"authenticator_app", MFAAuthenticatorApp, true},
		{"Authenticator_App", MFAAuthenticatorApp, true},
		{"sms", MFASMS, true},
		{"SMS", MFASMS, true},
		{"text", MFASMS, true},
		{" Text ", MFASMS, true},
		{"email", MFAEmail, true},
		{"EMail", MFAEmail, true},
		{"", "", false},
		{"carrier-pigeon", "", false},
		{"totp", "", false},
	}
	for _, tt := range tests {
		got, err := ParseMFAMethod(tt.in)
		if tt.ok != (err == nil) || got != tt.want {
			t.Errorf("ParseMFAMethod(%q) = %q, %v", tt.in, got, err)
		}
		if err != nil && !errors.Is(err, ErrMFAMethodUnsupported) {
			t.Errorf("ParseMFAMethod(%q) error %v does not wrap ErrMFAMethodUnsupported", tt.in, err)
		}
	}
	if MFASMS.String() != "sms" || MFAAuthenticatorApp.String() != "authenticator_app" || MFAEmail.String() != "email" {
		t.Error("String")
	}
}

func TestDestinationParsing(t *testing.T) {
	for in, want := range map[string]string{
		"A 6-digit code has been sent to your phone number ******0100": "******0100",
		"no hint": "", "**12": "**12", "*1": "", "x ***********1234567": "***********1234",
	} {
		if got := maskedDest.FindString(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// Concurrent, independent logins must not share state (run with -race).
func TestConcurrentLogins(t *testing.T) {
	f := newFake(t)
	f.defaultMFA = "sms"
	c := start(t, f)
	c1, c2 := roundTrip(t, c), roundTrip(t, c)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c1.String()
		_, _ = c1.MarshalBinary()
	}()
	_, _ = c2.MarshalBinary()
	<-done
}

func TestPickerLanding(t *testing.T) {
	tests := []struct {
		name    string
		picker  string
		opts    []LoginOption
		want    MFAMethod
		resend  bool
		wantLog []string
	}{
		// With no default the authenticator app is taken: choosing it sends nothing.
		{"prefers authenticator app", "", nil, MFAAuthenticatorApp, false, []string{"GET picker", "GET choose type=authenticator_app", "POST verify type=authenticator_app"}},
		{"explicit method", "", []LoginOption{WithMFAMethod(MFAEmail)}, MFAEmail, true, []string{"GET picker", "GET choose type=email", "POST verify type=email"}},
		{"explicit sms", "", []LoginOption{WithMFAMethod(MFASMS)}, MFASMS, true, []string{"GET picker", "GET choose type=sms", "POST verify type=sms"}},
		{"email before sms", "sms-email", nil, MFAEmail, true, []string{"GET picker", "GET choose type=email", "POST verify type=email"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			f.defaultMFA = "picker"
			f.pickerMode = tt.picker
			c := start(t, f, tt.opts...)
			if c.Method != tt.want || c.CanResend() != tt.resend || c.mfaType != string(tt.want) {
				t.Fatalf("challenge = %v (type %q)", c, c.mfaType)
			}
			complete(t, f, roundTrip(t, c))
			wantLog(t, f, tt.wantLog...)
		})
	}
	t.Run("method not offered", func(t *testing.T) {
		f := newFake(t)
		f.defaultMFA = "picker"
		f.pickerMode = "app-only"
		_, err := StartLogin(context.Background(), f.cfg(), testEmail, testPassword, WithMFAMethod(MFAEmail))
		if !errors.Is(err, ErrMFAMethodUnsupported) {
			t.Fatalf("err = %v", err)
		}
	})
}

// A rejected code comes back as a 200 re-render (as captured), a 422 or a
// redirect to the challenge page; all are a wrong code and leave the challenge
// usable.
func TestWrongCodeShapes(t *testing.T) {
	for _, mode := range []string{"", "422", "redirect"} {
		t.Run("mode "+mode, func(t *testing.T) {
			f := newFake(t)
			f.wrongMode = mode
			ctx := context.Background()
			c := start(t, f)
			old := c.csrf
			if _, err := CompleteLogin(ctx, f.cfg(), c, "000000"); !errors.Is(err, ErrInvalidMFACode) {
				t.Fatalf("err = %v", err)
			}
			if c.csrf == old {
				t.Error("tokens not refreshed")
			}
			complete(t, f, roundTrip(t, c))
		})
	}
}

func TestResendRedirect(t *testing.T) {
	f := newFake(t)
	f.defaultMFA = "email"
	f.resendMode = "redirect"
	c := start(t, f)
	stale := c.resendToken
	if err := ResendMFACode(context.Background(), f.cfg(), c); err != nil {
		t.Fatal(err)
	}
	if c.resendToken == stale {
		t.Error("resend token not refreshed from the page behind the redirect")
	}
	complete(t, f, c)
	wantLog(t, f, "GET new type=email", "POST resend type=email", "GET new type=email", "POST verify type=email")
}

// An expired login session sends the code POST back to the login page.
func TestVerifyAfterSessionLostIsExpired(t *testing.T) {
	f := newFake(t)
	c := start(t, f)
	f.wrongMode = "login"
	if _, err := CompleteLogin(context.Background(), f.cfg(), c, "000000"); !errors.Is(err, ErrMFAExpired) {
		t.Fatalf("err = %v", err)
	}
}

// A switch that fails (the picker has no such method) still gets a response
// that rotates the CSRF cookie; the original challenge must stay usable after
// it, also through a marshal round trip.
func TestFailedSwitchKeepsChallengeUsable(t *testing.T) {
	f := newFake(t)
	f.pickerMode = "no-sms"
	c := start(t, f)
	if err := SwitchMFAMethod(context.Background(), f.cfg(), c, MFASMS); !errors.Is(err, ErrMFAMethodUnsupported) {
		t.Fatalf("err = %v", err)
	}
	complete(t, f, roundTrip(t, c))
}

// Responses that cannot be used (a page without the form, say) can still
// replace the session cookie; a retry after a failed code or resend needs it.
func TestUnusableResponseKeepsSession(t *testing.T) {
	t.Run("code", func(t *testing.T) {
		f := newFake(t)
		f.wrongMode = "maintenance"
		c := start(t, f)
		if _, err := CompleteLogin(context.Background(), f.cfg(), c, "000000"); !errors.Is(err, ErrLoginFlowChanged) {
			t.Fatalf("err = %v", err)
		}
		f.wrongMode = ""
		complete(t, f, roundTrip(t, c))
	})
	t.Run("resend", func(t *testing.T) {
		f := newFake(t)
		f.defaultMFA = "email"
		f.resendMode = "maintenance"
		c := start(t, f)
		if err := ResendMFACode(context.Background(), f.cfg(), c); !errors.Is(err, ErrLoginFlowChanged) {
			t.Fatalf("err = %v", err)
		}
		f.resendMode = ""
		complete(t, f, roundTrip(t, c))
	})
}

// A picker that is recognized but offers nothing this library supports is
// known to offer none: Offered is empty, not nil (unknown), also after a round trip.
func TestOfferedEmptyIsNotUnknown(t *testing.T) {
	f := newFake(t)
	f.pickerMode = "unknown-only"
	c := start(t, f)
	if c.Offered != nil {
		t.Fatalf("Offered = %v before the picker was seen, want nil", c.Offered)
	}
	if err := SwitchMFAMethod(context.Background(), f.cfg(), c, MFASMS); !errors.Is(err, ErrMFAMethodUnsupported) {
		t.Fatalf("err = %v", err)
	}
	if c.Offered == nil || len(c.Offered) != 0 {
		t.Errorf("Offered = %#v, want an empty non-nil slice", c.Offered)
	}
	if got := roundTrip(t, c).Offered; got == nil || len(got) != 0 {
		t.Errorf("Offered after a round trip = %#v, want an empty non-nil slice", got)
	}
	// Landing on such a picker is an unsupported-method error, not a changed flow.
	g := newFake(t)
	g.defaultMFA = "picker"
	g.pickerMode = "unknown-only"
	if _, err := StartLogin(context.Background(), g.cfg(), testEmail, testPassword); !errors.Is(err, ErrMFAMethodUnsupported) {
		t.Errorf("err = %v", err)
	}
}

func TestOfferedMethods(t *testing.T) {
	t.Run("picker landing", func(t *testing.T) {
		for picker, want := range map[string][]MFAMethod{
			"":          {MFAAuthenticatorApp, MFASMS, MFAEmail},
			"no-sms":    {MFAAuthenticatorApp, MFAEmail},
			"app-only":  {MFAAuthenticatorApp},
			"sms-email": {MFASMS, MFAEmail},
		} {
			f := newFake(t)
			f.defaultMFA = "picker"
			f.pickerMode = picker
			c := start(t, f)
			if !slices.Equal(c.Offered, want) {
				t.Errorf("picker %q: Offered = %v, want %v", picker, c.Offered, want)
			}
			if got := roundTrip(t, c).Offered; !slices.Equal(got, want) {
				t.Errorf("picker %q: Offered after a round trip = %v", picker, got)
			}
		}
	})
	t.Run("unknown when the server picks a default", func(t *testing.T) {
		f := newFake(t)
		c := start(t, f)
		if c.Offered != nil {
			t.Errorf("Offered = %v, want nil (unknown)", c.Offered)
		}
	})
	t.Run("after a switch", func(t *testing.T) {
		f := newFake(t)
		c := start(t, f)
		if err := SwitchMFAMethod(context.Background(), f.cfg(), c, MFAEmail); err != nil {
			t.Fatal(err)
		}
		if want := []MFAMethod{MFAAuthenticatorApp, MFASMS, MFAEmail}; !slices.Equal(c.Offered, want) {
			t.Errorf("Offered = %v, want %v", c.Offered, want)
		}
	})
	t.Run("learned from a switch the account cannot make", func(t *testing.T) {
		f := newFake(t)
		f.pickerMode = "no-sms"
		c := start(t, f)
		if err := SwitchMFAMethod(context.Background(), f.cfg(), c, MFASMS); !errors.Is(err, ErrMFAMethodUnsupported) {
			t.Fatalf("err = %v", err)
		}
		if want := []MFAMethod{MFAAuthenticatorApp, MFAEmail}; !slices.Equal(c.Offered, want) {
			t.Errorf("Offered = %v, want %v", c.Offered, want)
		}
	})
	t.Run("with the method shortcut", func(t *testing.T) {
		f := newFake(t)
		f.defaultMFA = "sms"
		c := start(t, f, WithMFAMethod(MFAEmail))
		if want := []MFAMethod{MFAAuthenticatorApp, MFASMS, MFAEmail}; !slices.Equal(c.Offered, want) {
			t.Errorf("Offered = %v, want %v", c.Offered, want)
		}
	})
}
