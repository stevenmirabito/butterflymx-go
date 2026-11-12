package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stevenmirabito/butterflymx-go"
	"github.com/stevenmirabito/butterflymx-go/auth"
	"github.com/stevenmirabito/butterflymx-go/butterflymxtest"
)

type env struct {
	t     *testing.T
	srv   *butterflymxtest.Server
	token string
	vars  map[string]string
}

func newEnv(t *testing.T, opts ...butterflymxtest.Option) *env {
	t.Helper()
	srv := butterflymxtest.NewServer(opts...)
	t.Cleanup(srv.Close)
	return &env{t: t, srv: srv, token: filepath.Join(t.TempDir(), "cfg", "bmx", "token.json"), vars: map[string]string{}}
}

// bmx runs the CLI with the fake's URLs and returns exit code, stdout, stderr.
func (e *env) bmx(stdin string, args ...string) (int, string, string) {
	e.t.Helper()
	return e.bmxReader(strings.NewReader(stdin), args...)
}

func (e *env) bmxReader(stdin io.Reader, args ...string) (int, string, string) {
	e.t.Helper()
	u := e.srv.URL()
	full := append([]string{"--accounts-url", u, "--api-url", u, "--unlock-url", u, "--token-file", e.token}, args...)
	var out, errb bytes.Buffer
	code := run(context.Background(), full, stdin, &out, &errb, func(k string) string { return e.vars[k] })
	return code, out.String(), errb.String()
}

// lazyLines is a stdin that produces each line only when the CLI reads it, so
// a line can depend on what the fake server sent in response to an earlier one
// (for example the SMS code that the previous input triggered).
type lazyLines struct{ next []func() string }

func (l *lazyLines) Read(p []byte) (int, error) {
	if len(l.next) == 0 {
		return 0, io.EOF
	}
	f := l.next[0]
	l.next = l.next[1:]
	return copy(p, f()+"\n"), nil
}

func lit(s string) func() string { return func() string { return s } }

func (e *env) lastCode(method string) func() string {
	return func() string { return e.srv.LastMFACode(method) }
}

func (e *env) ok(args ...string) string {
	e.t.Helper()
	code, out, errs := e.bmx("", args...)
	if code != 0 {
		e.t.Fatalf("bmx %v: exit %d\nstdout: %s\nstderr: %s", args, code, out, errs)
	}
	return out
}

func (e *env) login() {
	e.t.Helper()
	e.vars["BMX_PASSWORD"] = butterflymxtest.DefaultPassword
	e.ok("login", "--email", butterflymxtest.DefaultEmail, "--code", e.srv.CurrentTOTP())
}

func (e *env) jsonOut(args ...string) any {
	e.t.Helper()
	out := e.ok(append([]string{"--json"}, args...)...)
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		e.t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	return v
}

// expireSession replaces the stored token with an expired one whose refresh
// token the server rejects.
func (e *env) expireSession() {
	e.t.Helper()
	tok := `{"access_token":"x","refresh_token":"bogus","expiry":"2020-01-01T00:00:00Z","api_token":"x"}`
	if err := os.WriteFile(e.token, []byte(tok), 0o600); err != nil {
		e.t.Fatal(err)
	}
}

func future(d time.Duration) string { return time.Now().Add(d).UTC().Format(time.RFC3339) }

func TestLoginPasswordEnvAndCode(t *testing.T) {
	e := newEnv(t)
	e.vars["BMX_PASSWORD"] = butterflymxtest.DefaultPassword
	out := e.ok("login", "--email", butterflymxtest.DefaultEmail, "--code", e.srv.CurrentTOTP())
	if !strings.Contains(out, "Logged in") || !strings.Contains(out, butterflymxtest.DefaultEmail) {
		t.Errorf("unexpected output: %s", out)
	}
	tokData, err := os.ReadFile(e.token)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "access_token") {
		t.Error("login printed a token")
	}
	var tok map[string]any
	if err := json.Unmarshal(tokData, &tok); err != nil || tok["api_token"] == "" {
		t.Errorf("token file lacks an api token: %v %s", err, tokData)
	}
}

func TestLoginWrongCodeRetriesViaStdin(t *testing.T) {
	e := newEnv(t)
	e.vars["BMX_PASSWORD"] = butterflymxtest.DefaultPassword
	code, out, errs := e.bmx("000000\n"+e.srv.CurrentTOTP()+"\n", "login", "--email", butterflymxtest.DefaultEmail)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(errs, "Invalid code (attempt 1 of 3)") {
		t.Errorf("no retry notice on stderr: %s", errs)
	}
	e.ok("whoami")
}

func TestLoginGivesUpAfterThreeWrongCodes(t *testing.T) {
	e := newEnv(t)
	e.vars["BMX_PASSWORD"] = butterflymxtest.DefaultPassword
	code, _, errs := e.bmx("000000\n000000\n000000\n", "login", "--email", butterflymxtest.DefaultEmail)
	if code != 1 || !strings.Contains(errs, "invalid two-factor code") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	if _, err := os.Stat(e.token); err == nil {
		t.Error("token file written after a failed login")
	}
}

func TestLoginMFAMethodFlagRejectsUnknown(t *testing.T) {
	e := newEnv(t)
	e.vars["BMX_PASSWORD"] = butterflymxtest.DefaultPassword
	code, _, errs := e.bmx("", "login", "--email", butterflymxtest.DefaultEmail, "--mfa-method", "bogus")
	if code != 2 || !strings.Contains(errs, "--mfa-method") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	if n := len(e.srv.Requests()); n != 0 {
		t.Errorf("the server saw %d requests for a usage error", n)
	}
}

func TestLoginDefaultAuthenticatorPrompt(t *testing.T) {
	e := newEnv(t)
	e.vars["BMX_PASSWORD"] = butterflymxtest.DefaultPassword
	code, out, errs := e.bmx(e.srv.CurrentTOTP()+"\n", "login", "--email", butterflymxtest.DefaultEmail)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(errs, "Enter the code from your authenticator app (or: sms / email):") {
		t.Errorf("prompt: %q", errs)
	}
	if n := len(e.srv.MFADeliveries()); n != 0 {
		t.Errorf("%d codes sent for an authenticator login", n)
	}
	e.ok("whoami")
}

func TestLoginMFAMethodSMS(t *testing.T) {
	e := newEnv(t)
	e.vars["BMX_PASSWORD"] = butterflymxtest.DefaultPassword
	in := &lazyLines{next: []func() string{e.lastCode("sms")}}
	code, out, errs := e.bmxReader(in, "login", "--email", butterflymxtest.DefaultEmail, "--mfa-method", "sms")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(errs, "Enter the 6-digit code sent by text to ******0100 (or: resend / email / app):") {
		t.Errorf("prompt: %q", errs)
	}
	if e.srv.LastMFACode("sms") == "" {
		t.Fatal("no SMS code was sent")
	}
	for _, d := range e.srv.MFADeliveries() {
		if d.Method != "sms" {
			t.Errorf("unexpected delivery %+v", d)
		}
	}
	e.ok("whoami")
}

func TestLoginMFAMethodEmail(t *testing.T) {
	e := newEnv(t)
	e.vars["BMX_PASSWORD"] = butterflymxtest.DefaultPassword
	in := &lazyLines{next: []func() string{e.lastCode("email")}}
	code, out, errs := e.bmxReader(in, "login", "--email", butterflymxtest.DefaultEmail, "--mfa-method", "email")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(errs, "Enter the 6-digit code sent by email (or: resend / sms / app):") {
		t.Errorf("prompt: %q", errs)
	}
	if e.srv.LastMFACode("email") == "" || e.srv.LastMFACode("sms") != "" {
		t.Errorf("deliveries: %+v", e.srv.MFADeliveries())
	}
	e.ok("whoami")
}

func TestLoginResendThenCode(t *testing.T) {
	e := newEnv(t)
	e.vars["BMX_PASSWORD"] = butterflymxtest.DefaultPassword
	in := &lazyLines{next: []func() string{lit("resend"), e.lastCode("sms")}}
	code, out, errs := e.bmxReader(in, "login", "--email", butterflymxtest.DefaultEmail, "--mfa-method", "sms")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(errs, "Code sent by text to ******0100.") {
		t.Errorf("no resend confirmation: %q", errs)
	}
	var resends int
	for _, d := range e.srv.MFADeliveries() {
		if d.Trigger == "resend" {
			resends++
		}
	}
	if resends != 1 {
		t.Errorf("resend deliveries = %d, want 1: %+v", resends, e.srv.MFADeliveries())
	}
	e.ok("whoami")
}

func TestLoginResendNotForAuthenticator(t *testing.T) {
	e := newEnv(t)
	e.vars["BMX_PASSWORD"] = butterflymxtest.DefaultPassword
	code, out, errs := e.bmx("resend\n"+e.srv.CurrentTOTP()+"\n", "login", "--email", butterflymxtest.DefaultEmail)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(errs, "no code to resend") {
		t.Errorf("stderr: %q", errs)
	}
}

func TestLoginSwitchMethodAtPrompt(t *testing.T) {
	e := newEnv(t, butterflymxtest.WithLastMFAMethod("sms"))
	e.vars["BMX_PASSWORD"] = butterflymxtest.DefaultPassword
	in := &lazyLines{next: []func() string{lit("email"), e.lastCode("email")}}
	code, out, errs := e.bmxReader(in, "login", "--email", butterflymxtest.DefaultEmail)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(errs, "code sent by text to ******0100 (or: resend / email / app)") {
		t.Errorf("first prompt should name the SMS default: %q", errs)
	}
	if !strings.Contains(errs, "Code sent by email.") || !strings.Contains(errs, "sent by email (or: resend / sms / app)") {
		t.Errorf("no switch confirmation or new prompt: %q", errs)
	}
	var sms, email int
	for _, d := range e.srv.MFADeliveries() {
		switch d.Method {
		case "sms":
			sms++
		case "email":
			email++
		}
	}
	if sms == 0 || email == 0 {
		t.Errorf("deliveries: %+v", e.srv.MFADeliveries())
	}
	e.ok("whoami")
}

func TestLoginSwitchToAuthenticatorApp(t *testing.T) {
	e := newEnv(t, butterflymxtest.WithLastMFAMethod("sms"))
	e.vars["BMX_PASSWORD"] = butterflymxtest.DefaultPassword
	in := &lazyLines{next: []func() string{lit("app"), func() string { return e.srv.CurrentTOTP() }}}
	code, out, errs := e.bmxReader(in, "login", "--email", butterflymxtest.DefaultEmail)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(errs, "Switched to the authenticator app.") || !strings.Contains(errs, "Enter the code from your authenticator app") {
		t.Errorf("stderr: %q", errs)
	}
}

func TestLoginSMSWrongCodeThenRight(t *testing.T) {
	e := newEnv(t)
	e.vars["BMX_PASSWORD"] = butterflymxtest.DefaultPassword
	in := &lazyLines{next: []func() string{lit("000000"), e.lastCode("sms")}}
	code, out, errs := e.bmxReader(in, "login", "--email", butterflymxtest.DefaultEmail, "--mfa-method", "sms")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(errs, "Invalid code (attempt 1 of 3)") {
		t.Errorf("no retry notice: %q", errs)
	}
}

func TestLoginSwitchesDoNotCountAsAttempts(t *testing.T) {
	e := newEnv(t)
	e.vars["BMX_PASSWORD"] = butterflymxtest.DefaultPassword
	in := &lazyLines{next: []func() string{lit("000000"), lit("resend"), lit("000000"), lit("resend"), e.lastCode("sms")}}
	code, out, errs := e.bmxReader(in, "login", "--email", butterflymxtest.DefaultEmail, "--mfa-method", "sms")
	if code != 0 || !strings.Contains(errs, "attempt 2 of 3") || strings.Contains(errs, "attempt 3 of 3") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
}

func TestLoginCodeFromEnvSkipsPrompt(t *testing.T) {
	e := newEnv(t)
	e.vars["BMX_PASSWORD"] = butterflymxtest.DefaultPassword
	e.vars["BMX_TOTP_CODE"] = e.srv.CurrentTOTP()
	code, out, errs := e.bmx("", "login", "--email", butterflymxtest.DefaultEmail)
	if code != 0 || strings.Contains(errs, "Enter the") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
	// A wrong preset code is used as is, then the prompt takes over.
	e.vars["BMX_TOTP_CODE"] = "000000"
	code, _, errs = e.bmx(e.srv.CurrentTOTP()+"\n", "login", "--email", butterflymxtest.DefaultEmail)
	if i := strings.Index(errs, "Invalid code"); code != 0 || i < 0 || i > strings.Index(errs, "Enter the") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
}

func TestLoginPasswordStdinAndWrongPassword(t *testing.T) {
	e := newEnv(t)
	code, _, errs := e.bmx("nope\n", "login", "--email", butterflymxtest.DefaultEmail, "--password-stdin", "--code", "123456")
	if code != 1 || !strings.Contains(errs, "invalid email or password") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	code, _, errs = e.bmx(butterflymxtest.DefaultPassword+"\n", "login", "--email", butterflymxtest.DefaultEmail, "--password-stdin", "--code", e.srv.CurrentTOTP())
	if code != 0 {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
}

func TestLoginBrowserFlow(t *testing.T) {
	e := newEnv(t)
	// The paste prompt gets a URL with the wrong state: the flow must reject it
	// without writing a token, which exercises Start/Finish wiring.
	code, _, errs := e.bmx("com.butterflymx.oauth://oauth?code=abc&state=wrong\n", "login", "--browser")
	if code != 1 {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	if !strings.Contains(errs, "Open this URL") || !strings.Contains(errs, "/oauth/authorize") {
		t.Errorf("authorize URL not printed: %q", errs)
	}
	if _, err := os.Stat(e.token); err == nil {
		t.Error("token written after a rejected redirect")
	}
}

func TestWhoamiTenantsDoors(t *testing.T) {
	e := newEnv(t)
	e.login()
	out := e.ok("whoami")
	if !strings.Contains(out, butterflymxtest.DefaultEmail) {
		t.Errorf("whoami: %s", out)
	}
	seed := e.srv.Seed()
	out = e.ok("tenants")
	if !strings.Contains(out, seed.TenantGlobalID) || !strings.Contains(out, seed.UnitLabel) {
		t.Errorf("tenants: %s", out)
	}
	out = e.ok("doors")
	for _, ap := range seed.AccessPoints {
		if !strings.Contains(out, ap.Name) {
			t.Errorf("doors lacks %q:\n%s", ap.Name, out)
		}
	}
	doors := e.jsonOut("doors", "--tenant", seed.TenantID).([]any)
	if len(doors) != len(seed.AccessPoints) {
		t.Errorf("got %d doors, want %d", len(doors), len(seed.AccessPoints))
	}
}

func TestPassesCustomLifecycle(t *testing.T) {
	e := newEnv(t)
	e.login()
	out := e.ok("passes", "create", "--name", "Dog walker", "--door", "bike room", "--door", "Garage Gate",
		"--start", future(time.Hour), "--end", future(3*time.Hour), "--to", "Walker=walker@example.com", "--to", "(555) 010-0199")
	if !strings.Contains(out, "PIN:") || !strings.Contains(out, "QR:") || !strings.Contains(out, "instructions:") {
		t.Errorf("create output lacks key details:\n%s", out)
	}
	ks := e.srv.Keychains()
	var created butterflymxtest.Keychain
	for _, k := range ks {
		if k.Name == "Dog walker" {
			created = k
		}
	}
	if created.ID == "" || len(created.VirtualKeys) != 2 || len(created.AccessPointIDs) != 2 {
		t.Fatalf("fake state: %+v", created)
	}
	if !strings.Contains(out, created.VirtualKeys[0].PIN) {
		t.Errorf("PIN missing from output:\n%s", out)
	}

	get := e.ok("passes", "get", created.ID)
	if !strings.Contains(get, created.VirtualKeys[1].PIN) || !strings.Contains(get, "Dog walker") {
		t.Errorf("get:\n%s", get)
	}

	list := e.ok("passes", "list", "--kind", "custom")
	if !strings.Contains(list, "Dog walker") || strings.Contains(list, created.VirtualKeys[0].PIN) {
		t.Errorf("list should show the pass and no PINs:\n%s", list)
	}
	listJSON := e.ok("--json", "passes", "list")
	for _, v := range created.VirtualKeys {
		if strings.Contains(listJSON, v.PIN) || strings.Contains(listJSON, "qr_code") {
			t.Error("list --json leaked a secret")
		}
	}
	expired := e.ok("passes", "list", "--status", "expired")
	if strings.Contains(expired, "Dog walker") {
		t.Errorf("new pass listed as expired:\n%s", expired)
	}

	e.ok("passes", "delete", created.ID)
	code, _, errs := e.bmx("", "passes", "get", created.ID)
	if code != 1 || !strings.Contains(errs, "404") {
		t.Errorf("get after delete: exit %d %q", code, errs)
	}
}

func TestPassesCreateRecurring(t *testing.T) {
	e := newEnv(t)
	e.login()
	start := time.Now().AddDate(0, 0, 1).Format("2006-01-02")
	end := time.Now().AddDate(0, 0, 30).Format("2006-01-02")
	out := e.ok("passes", "create", "--name", "Cleaner", "--door", "Front Door", "--weekdays", "mon,wed",
		"--from", "09:00", "--to", "17:00", "--start-date", start, "--end-date", end, "--to", "cleaner@example.com")
	if !strings.Contains(out, "recurring") || !strings.Contains(out, "mon,wed 09:00-17:00") {
		t.Errorf("create recurring:\n%s", out)
	}
	var found bool
	for _, k := range e.srv.Keychains() {
		if k.Name == "Cleaner" {
			found = true
			if k.Kind != "recurring" || k.TimeFrom != "09:00" || k.TimeTo != "17:00" {
				t.Errorf("fake state: %+v", k)
			}
		}
	}
	if !found {
		t.Fatal("recurring pass not created")
	}
	// The unambiguous spelling works too.
	e.ok("passes", "create", "--name", "Cleaner 2", "--door", "Front Door", "--weekdays", "fri",
		"--from", "09:00", "--until", "10:00", "--start-date", start, "--end-date", end, "--to", "cleaner@example.com")
}

func TestKeysAddRevoke(t *testing.T) {
	e := newEnv(t)
	e.login()
	e.ok("passes", "create", "--name", "Guests", "--door", "Main Entrance", "--start", future(time.Hour),
		"--end", future(5*time.Hour), "--to", "a@example.com")
	var id string
	for _, k := range e.srv.Keychains() {
		if k.Name == "Guests" {
			id = k.ID
		}
	}
	out := e.ok("keys", "add", id, "--to", "Bob=bob@example.com")
	if !strings.Contains(out, "PIN:") || !strings.Contains(out, "bob@example.com") {
		t.Errorf("keys add:\n%s", out)
	}
	var keys []butterflymxtest.VirtualKey
	for _, k := range e.srv.Keychains() {
		if k.ID == id {
			keys = k.VirtualKeys
		}
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 keys, have %d", len(keys))
	}
	e.ok("keys", "revoke", id, keys[1].ID)
	for _, k := range e.srv.Keychains() {
		if k.ID == id && len(k.VirtualKeys) != 1 {
			t.Errorf("after revoke: %d keys", len(k.VirtualKeys))
		}
	}
}

func TestDeliveryCreateRenameExtend(t *testing.T) {
	e := newEnv(t)
	e.login()
	out := e.ok("delivery", "create", "--name", "Groceries")
	if !strings.Contains(out, "PIN:") {
		t.Errorf("delivery create:\n%s", out)
	}
	var id string
	for _, k := range e.srv.Keychains() {
		if k.Name == "Groceries" {
			id = k.ID
		}
	}
	if id == "" {
		t.Fatal("delivery pass not created")
	}
	var before time.Time
	for _, k := range e.srv.Keychains() {
		if k.ID == id {
			before = k.EndsAt
		}
	}
	out = e.ok("delivery", "rename", id, "Pizza")
	if !strings.Contains(out, "Pizza") || strings.Contains(out, "PIN:") && !strings.Contains(out, "PIN:          -") {
		t.Errorf("rename:\n%s", out)
	}
	e.ok("delivery", "extend", id, "--days", "10")
	for _, k := range e.srv.Keychains() {
		if k.ID == id {
			if k.Name != "Pizza" {
				t.Errorf("name = %q", k.Name)
			}
			if d := k.EndsAt.Sub(before); d < 10*24*time.Hour-time.Minute || d > 10*24*time.Hour+time.Minute {
				t.Errorf("extended by %s", d)
			}
		}
	}
}

func TestUnlockHistoryRaw(t *testing.T) {
	e := newEnv(t)
	e.login()
	out := e.ok("unlock", "--door", "main entrance")
	if !strings.Contains(out, "Unlock requested") {
		t.Errorf("unlock:\n%s", out)
	}
	if n := len(e.srv.Unlocks()); n != 1 {
		t.Errorf("fake saw %d unlocks", n)
	}

	for _, kind := range []string{"doors", "calls", "messages"} {
		arr := e.jsonOut("history", kind, "--limit", "2").([]any)
		if len(arr) == 0 || len(arr) > 2 {
			t.Errorf("history %s returned %d entries", kind, len(arr))
		}
		e.ok("history", kind)
	}

	gq := e.ok("raw", "graphql", "--op", "CurrentUser", "--query", "query CurrentUser { currentUser { email } }")
	if !strings.Contains(gq, butterflymxtest.DefaultEmail) {
		t.Errorf("raw graphql:\n%s", gq)
	}
	rest := e.ok("raw", "rest", "GET", "/v3/access_codes?filter[status]=active&filter[tenant]="+e.srv.Seed().TenantID)
	if !strings.Contains(rest, `"data"`) {
		t.Errorf("raw rest:\n%s", rest)
	}
	code, _, errs := e.bmx("", "raw", "rest", "GET", "/v3/nope")
	if code != 1 || !strings.Contains(errs, "404") {
		t.Errorf("raw rest 404: exit %d %q", code, errs)
	}
}

// serverLogouts counts the sign-out calls the fake received.
func serverLogouts(e *env) int {
	n := 0
	for _, r := range e.srv.Requests() {
		if r.Method == http.MethodDelete && r.Path == "/denizen/v1/logout" {
			n++
		}
	}
	return n
}

func TestLogout(t *testing.T) {
	e := newEnv(t)
	e.login()
	if out := e.ok("logout"); !strings.Contains(out, "Logged out.") {
		t.Errorf("output %q", out)
	}
	if n := serverLogouts(e); n != 1 {
		t.Errorf("server logout called %d times, want 1", n)
	}
	if _, err := os.Stat(e.token); err == nil {
		t.Error("token file still exists")
	}
	code, _, errs := e.bmx("", "whoami")
	if code != 1 || !strings.Contains(errs, "not logged in: run `bmx login`") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	// Idempotent: nothing to do, and no second server call.
	if out := e.ok("logout"); !strings.Contains(out, "Not logged in; nothing to do.") {
		t.Errorf("output %q", out)
	}
	if n := serverLogouts(e); n != 1 {
		t.Errorf("server logout called %d times after the second logout, want 1", n)
	}
}

func TestLogoutJSON(t *testing.T) {
	e := newEnv(t, butterflymxtest.WithClock(time.Now))
	e.login()
	if m, _ := e.jsonOut("logout").(map[string]any); m["logged_out"] != true {
		t.Errorf("logout JSON %v", m)
	}
	if m, _ := e.jsonOut("logout").(map[string]any); m["logged_out"] != false {
		t.Errorf("second logout JSON %v", m)
	}
}

func TestLogoutServerFailureStillRemovesToken(t *testing.T) {
	e := newEnv(t)
	e.login()
	e.srv.FailNext(http.MethodDelete, "/denizen/v1/logout", 500, 5)
	code, _, errs := e.bmx("", "logout")
	if code != 1 || !strings.Contains(errs, "local token removed, but server-side logout failed") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	if _, err := os.Stat(e.token); err == nil {
		t.Error("token file still exists after a failed server logout")
	}
}

func TestLogoutCorruptTokenFile(t *testing.T) {
	e := newEnv(t)
	if err := os.MkdirAll(filepath.Dir(e.token), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.token, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.ok("logout")
	if _, err := os.Stat(e.token); err == nil {
		t.Error("corrupt token file still exists")
	}
	if n := serverLogouts(e); n != 0 {
		t.Errorf("server logout called %d times for a corrupt file", n)
	}
}

// ---- environment and region ----

func writeToken(t *testing.T, path, region string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	tok := `{"access_token":"x","refresh_token":"r","expiry":"` + future(time.Hour) + `","api_token":"x","region":"` + region + `"}`
	if err := os.WriteFile(path, []byte(tok), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEnvironmentForTokenRegion(t *testing.T) {
	eu, na := &auth.Token{Region: "eu"}, &auth.Token{Region: "na"}
	tests := []struct {
		name                  string
		env                   string
		accounts, api, unlock string
		tok                   *auth.Token
		want                  butterflymx.Environment
	}{
		{name: "no flags, eu token", tok: eu, want: butterflymx.ProductionEU},
		{name: "no flags, na token", tok: na, want: butterflymx.Production},
		{name: "no flags, no region", tok: &auth.Token{}, want: butterflymx.Production},
		{name: "no flags, no token", want: butterflymx.Production},
		{name: "explicit production wins", env: "production", tok: eu, want: butterflymx.Production},
		{name: "explicit staging wins", env: "staging", tok: eu, want: butterflymx.Staging},
		{name: "explicit eu with na token", env: "production-eu", tok: na, want: butterflymx.ProductionEU},
		{name: "api override wins", api: "http://127.0.0.1:1/", tok: eu, want: withURLs(butterflymx.Production, "", "http://127.0.0.1:1", "")},
		{name: "accounts override wins", accounts: "http://127.0.0.1:2", tok: eu, want: withURLs(butterflymx.Production, "http://127.0.0.1:2", "", butterflymx.Production.UnlockURL)},
		{name: "unlock override wins", unlock: "http://127.0.0.1:3", tok: eu, want: withURLs(butterflymx.Production, "", "", "http://127.0.0.1:3")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &app{envName: tt.env, getenv: func(string) string { return "" }, tokenFile: filepath.Join(t.TempDir(), "token.json")}
			if err := a.setupEnv(tt.accounts, tt.api, tt.unlock); err != nil {
				t.Fatal(err)
			}
			got, err := a.environmentFor(tt.tok)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("environment = %+v, want %+v", got, tt.want)
			}
			if a.acfg.AccountsURL != a.benv.AccountsURL || a.acfg.APIURL != a.benv.APIURL {
				t.Errorf("auth config %s/%s disagrees with environment %s/%s", a.acfg.AccountsURL, a.acfg.APIURL, a.benv.AccountsURL, a.benv.APIURL)
			}
		})
	}
}

// withURLs overrides the non-empty URLs of env the way the CLI flags do: an
// API override clears the unlock URL.
func withURLs(env butterflymx.Environment, accounts, api, unlock string) butterflymx.Environment {
	if accounts != "" {
		env.AccountsURL = accounts
	}
	if api != "" {
		env.APIURL, env.UnlockURL = api, ""
	}
	if unlock != "" {
		env.UnlockURL = unlock
	}
	return env
}

func TestUnknownTokenRegionAsksForEnv(t *testing.T) {
	e := newEnv(t)
	writeToken(t, e.token, "mars")
	// No flags: the region is unknown, so nothing is sent anywhere.
	var out, errb bytes.Buffer
	code := run(context.Background(), []string{"--token-file", e.token, "whoami"}, strings.NewReader(""), &out, &errb, func(string) string { return "" })
	if code != 1 || !strings.Contains(errb.String(), "unknown region") || !strings.Contains(errb.String(), "--env") {
		t.Errorf("exit %d, stderr %q", code, errb.String())
	}
	if len(e.srv.Requests()) != 0 {
		t.Error("requests were sent")
	}
}

func TestExplicitFlagsWinOverTokenRegion(t *testing.T) {
	e := newEnv(t)
	e.login()
	// Pretend the account is in the EU: the explicit URLs of bmx (the fake)
	// must still be used, not eu.api.butterflymx.com.
	tok, err := os.ReadFile(e.token)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(tok, &m); err != nil {
		t.Fatal(err)
	}
	m["region"] = "eu"
	b, _ := json.Marshal(m)
	if err := os.WriteFile(e.token, b, 0o600); err != nil {
		t.Fatal(err)
	}
	e.ok("whoami")
	e.ok("logout")
	if n := serverLogouts(e); n != 1 {
		t.Errorf("server logout called %d times, want 1", n)
	}
}

func TestTokenFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	e := newEnv(t)
	e.login()
	fi, err := os.Stat(e.token)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("token file mode %v", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(e.token))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("token dir mode %v", di.Mode().Perm())
	}
}

func TestDefaultTokenPath(t *testing.T) {
	e := newEnv(t)
	e.vars["XDG_CONFIG_HOME"] = filepath.Join(t.TempDir(), "xdg")
	u := e.srv.URL()
	var out, errb bytes.Buffer
	run(context.Background(), []string{"--accounts-url", u, "--api-url", u, "whoami"}, strings.NewReader(""), &out, &errb, func(k string) string { return e.vars[k] })
	if !strings.Contains(errb.String(), "not logged in") {
		t.Errorf("stderr %q", errb.String())
	}
	e.vars["XDG_CONFIG_HOME"] = ""
	e.vars["HOME"] = "/nonexistent-home"
	a := &app{envName: "production", getenv: func(k string) string { return e.vars[k] }}
	if err := a.setupEnv("", "", ""); err != nil || a.tokenFile != "/nonexistent-home/.config/bmx/token.json" {
		t.Errorf("fallback path %q, err %v", a.tokenFile, err)
	}
}

func TestUsageErrors(t *testing.T) {
	e := newEnv(t)
	cases := [][]string{
		{},
		{"bogus"},
		{"--env", "mars", "whoami"},
		{"--nonsense"},
		{"passes"},
		{"passes", "frobnicate"},
		{"passes", "update", "1", "--name", "x"}, // guest passes are immutable
		{"delivery", "create", "--door", "a"},    // delivery passes always cover every door
		{"passes", "create", "--name", "x"},
		{"passes", "create", "--name", "x", "--door", "a", "--to", "a@example.com", "--start", "2026-01-01T00:00:00Z"},
		{"passes", "create", "--name", "x", "--door", "a", "--to", "a@example.com", "--start", "nope", "--end", "nope"},
		{"passes", "create", "--name", "x", "--door", "a", "--to", "not-an-address", "--start", future(time.Hour), "--end", future(2 * time.Hour)},
		{"passes", "list", "--status", "weird"},
		{"passes", "get", "abc"},
		{"keys", "revoke", "1"},
		{"unlock"},
		{"history"},
		{"history", "weird"},
		{"raw", "graphql", "--op", "X"},
		{"raw", "rest", "GET"},
		{"probe", "only:nope"},
		{"delivery", "extend"},
	}
	for _, args := range cases {
		code, _, errs := e.bmx("", args...)
		if code != 2 {
			t.Errorf("bmx %v: exit %d, want 2 (stderr %q)", args, code, errs)
		}
	}
	// Help is not an error.
	if code, out, _ := e.bmx("", "help"); code != 0 || !strings.Contains(out, "Usage:") {
		t.Errorf("help: exit %d", code)
	}
}

func TestNotLoggedIn(t *testing.T) {
	e := newEnv(t)
	for _, args := range [][]string{{"whoami"}, {"tenants"}, {"doors"}, {"passes", "list"}, {"probe"}} {
		code, _, errs := e.bmx("", args...)
		if code != 1 || !strings.Contains(errs, "not logged in: run `bmx login`") {
			t.Errorf("%v: exit %d, stderr %q", args, code, errs)
		}
	}
}

func TestRevokedSessionAsksToLogin(t *testing.T) {
	e := newEnv(t)
	e.login()
	e.expireSession()
	code, _, errs := e.bmx("", "whoami")
	if code != 1 || !strings.Contains(errs, "bmx login") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
}

func TestAmbiguousDoor(t *testing.T) {
	e := newEnv(t)
	e.login()
	code, _, errs := e.bmx("", "unlock", "--door", "door")
	if code != 1 || !strings.Contains(errs, "ambiguous") || !strings.Contains(errs, "Side Door") || !strings.Contains(errs, "Front Door") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	if len(e.srv.Unlocks()) != 0 {
		t.Error("an ambiguous door was unlocked")
	}
	code, _, errs = e.bmx("", "unlock", "--door", "ballroom")
	if code != 1 || !strings.Contains(errs, "no door matches") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	// An exact name wins over longer names that contain it.
	e.ok("unlock", "--door", "SIDE DOOR")
}

func TestVerboseDoesNotLeakTokens(t *testing.T) {
	e := newEnv(t)
	e.login()
	tokData, _ := os.ReadFile(e.token)
	var tok map[string]any
	_ = json.Unmarshal(tokData, &tok)
	code, out, errs := e.bmx("", "-v", "whoami")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, k := range []string{"access_token", "refresh_token", "api_token"} {
		if s, _ := tok[k].(string); s != "" && (strings.Contains(out, s) || strings.Contains(errs, s)) {
			t.Errorf("%s leaked", k)
		}
	}
}

// ---- probe ----

func probeResults(t *testing.T, e *env, args ...string) map[string]probeResult {
	t.Helper()
	v := e.ok(append([]string{"--json", "probe"}, args...)...)
	var rs []probeResult
	if err := json.Unmarshal([]byte(v), &rs); err != nil {
		t.Fatalf("probe JSON: %v\n%s", err, v)
	}
	m := map[string]probeResult{}
	for _, r := range rs {
		m[r.Name] = r
	}
	return m
}

func detail(r probeResult, key string) string {
	for _, kv := range r.Details {
		if kv.Key == key {
			return kv.Value
		}
	}
	return ""
}

func TestProbeReadOnly(t *testing.T) {
	e := newEnv(t)
	e.login()
	before := len(e.srv.Keychains())
	rs := probeResults(t, e)
	for _, n := range []string{"token", "statuses", "qr"} {
		if rs[n].Outcome == outFailed {
			t.Errorf("%s failed: %+v", n, rs[n])
		}
	}
	if !strings.Contains(detail(rs["token"], "current_user_call"), "ok") {
		t.Errorf("token probe: %+v", rs["token"])
	}
	if got := detail(rs["statuses"], "status=active"); !strings.Contains(got, "passes (") || !strings.Contains(got, "distinct set") {
		t.Errorf("statuses active = %q", got)
	}
	if got := detail(rs["statuses"], "status=upcoming"); !strings.Contains(got, "same set as all, inactive") {
		t.Errorf("statuses upcoming = %q", got)
	}
	if _, ok := rs["introspection"]; ok {
		t.Errorf("introspection probe must not exist (it could trip security monitoring)")
	}
	for _, n := range []string{"validation"} {
		if rs[n].Outcome != outSkipped || !strings.Contains(rs[n].Reason, "--allow-mutations") {
			t.Errorf("%s should be skipped for mutations: %+v", n, rs[n])
		}
	}
	if len(e.srv.Keychains()) != before {
		t.Error("read-only probes changed the fake")
	}
	// Human output never contains the QR URL (a credential).
	human := e.ok("probe", "only:qr")
	if strings.Contains(human, "http") {
		t.Errorf("qr probe printed a URL:\n%s", human)
	}
	if !strings.Contains(human, "== qr") {
		t.Errorf("human output:\n%s", human)
	}
}

func TestProbeMutationNeedsRecipient(t *testing.T) {
	e := newEnv(t)
	e.login()
	rs := probeResults(t, e, "--allow-mutations", "only:validation")
	for _, n := range []string{"validation"} {
		if rs[n].Outcome != outSkipped || !strings.Contains(rs[n].Reason, "--to") {
			t.Errorf("%s: %+v", n, rs[n])
		}
	}
	if rs["token"].Name != "" {
		t.Error("only: filter ignored")
	}
}

func TestProbeValidationShapes(t *testing.T) {
	e := newEnv(t)
	e.login()
	before := len(e.srv.Keychains())
	rs := probeResults(t, e, "--allow-mutations", "--to", "probe@example.com", "only:validation")

	v := rs["validation"]
	if v.Outcome == outFailed {
		t.Fatalf("validation: %+v", v)
	}
	if got := detail(v, "end_before_start"); !strings.HasPrefix(got, "HTTP 400") ||
		!strings.Contains(got, "Start time must be before the end time") || !strings.Contains(got, "/data/attributes/ends_at") {
		t.Errorf("end_before_start = %q", got)
	}
	if got := detail(v, "duration_400_days"); !strings.HasPrefix(got, "HTTP 400") || !strings.Contains(got, "cannot exceed 365 days from start date") {
		t.Errorf("duration_400_days = %q", got)
	}
	if got := detail(v, "door_without_virtual_keys"); !strings.HasPrefix(got, "HTTP 4") {
		t.Errorf("door_without_virtual_keys = %q", got)
	}
	if got := detail(v, "duration_400_days"); got == "" {
		t.Error("no 400-day result")
	}

	if n := len(e.srv.Keychains()); n != before {
		t.Errorf("probes left %d passes behind", n-before)
	}
}

// lenientProxy forwards to the fake but rewrites the pass-creation body so
// that its window becomes valid (one hour long), which makes the fake accept
// requests the probe expects to be rejected.
func lenientProxy(t *testing.T, target string) string {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	rp := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(u)
		if pr.In.Method != http.MethodPost || pr.In.URL.Path != "/v3/keychains/custom" {
			return
		}
		raw, _ := io.ReadAll(pr.In.Body)
		var doc struct {
			Data struct {
				Type          string         `json:"type"`
				Attributes    map[string]any `json:"attributes"`
				Relationships any            `json:"relationships"`
			} `json:"data"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Errorf("proxy: %v", err)
			return
		}
		starts, err := time.Parse(time.RFC3339, doc.Data.Attributes["starts_at"].(string))
		if err != nil {
			t.Errorf("proxy: %v", err)
			return
		}
		doc.Data.Attributes["ends_at"] = starts.Add(time.Hour).UTC().Format("2006-01-02T15:04:05Z")
		raw, _ = json.Marshal(doc)
		pr.Out.Body = io.NopCloser(bytes.NewReader(raw))
		pr.Out.ContentLength = int64(len(raw))
	}}
	srv := httptest.NewServer(rp)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestProbeValidationFlagsAcceptedCreate(t *testing.T) {
	e := newEnv(t)
	e.login()
	u := lenientProxy(t, e.srv.URL())
	var out, errb bytes.Buffer
	args := []string{"--accounts-url", u, "--api-url", u, "--unlock-url", u, "--token-file", e.token,
		"--json", "probe", "--allow-mutations", "--to", "probe@example.com", "only:validation"}
	code := run(context.Background(), args, strings.NewReader(""), &out, &errb, func(string) string { return "" })
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out.String(), errb.String())
	}
	var rs []probeResult
	if err := json.Unmarshal(out.Bytes(), &rs); err != nil || len(rs) != 1 {
		t.Fatalf("probe JSON: %v\n%s", err, out.String())
	}
	v := rs[0]
	if v.Outcome != outUnexpected || !strings.Contains(v.Reason, "deleted again") {
		t.Errorf("accepted create not flagged: %+v", v)
	}
	for _, k := range []string{"end_before_start", "duration_400_days"} {
		if got := detail(v, k); !strings.Contains(got, "ACCEPTED") {
			t.Errorf("%s = %q, want ACCEPTED", k, got)
		}
	}
	if got := detail(v, "cleanup"); !strings.Contains(got, "deleted pass") {
		t.Errorf("cleanup = %q", got)
	}
	for _, k := range e.srv.Keychains() {
		if strings.HasPrefix(k.Name, "bmx probe") {
			t.Errorf("probe pass %q left behind", k.Name)
		}
	}
}

func TestProbeValidationSendsInvalidRequestsUnvalidated(t *testing.T) {
	// The probe must reach the server with an end before the start; the
	// library's own validation would have stopped it.
	e := newEnv(t)
	e.login()
	probeResults(t, e, "--allow-mutations", "--to", "probe@example.com", "only:validation")
	found := false
	for _, r := range e.srv.Requests() {
		if r.Method == http.MethodPost && r.Path == "/v3/keychains/custom" && r.Status == http.StatusBadRequest {
			found = true
		}
	}
	if !found {
		t.Error("no rejected pass creation reached the server")
	}
}

func TestProbeTokenReportsFailure(t *testing.T) {
	e := newEnv(t)
	e.login()
	e.expireSession()
	code, out, _ := e.bmx("", "--json", "probe", "only:token")
	if code != 1 || !strings.Contains(out, `"failed"`) {
		t.Errorf("exit %d\n%s", code, out)
	}
}
