package auth

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const challengeV = 3

// MFAMethod is a two-factor method.
type MFAMethod string

const (
	MFAAuthenticatorApp MFAMethod = "authenticator_app"
	MFASMS              MFAMethod = "sms"
	MFAEmail            MFAMethod = "email"
)

// String returns the method's wire name ("authenticator_app", "sms", "email").
func (m MFAMethod) String() string { return string(m) }

func (m MFAMethod) valid() bool {
	return m == MFAAuthenticatorApp || m == MFASMS || m == MFAEmail
}

// ParseMFAMethod parses a method name, case-insensitively: "app",
// "authenticator" and "authenticator_app" mean [MFAAuthenticatorApp], "sms" and
// "text" mean [MFASMS], and "email" means [MFAEmail]. Anything else returns
// an error wrapping [ErrMFAMethodUnsupported].
func ParseMFAMethod(s string) (MFAMethod, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "app", "authenticator", "authenticator_app":
		return MFAAuthenticatorApp, nil
	case "sms", "text":
		return MFASMS, nil
	case "email":
		return MFAEmail, nil
	}
	return "", fmt.Errorf("%w: %q", ErrMFAMethodUnsupported, s)
}

// ErrMFAResendUnsupported is returned by [ResendMFACode] for methods that have
// no code to resend (authenticator_app).
var ErrMFAResendUnsupported = errors.New("auth: two-factor method cannot resend a code")

// MFAChallenge is a resumable, serializable half-finished login. It contains
// session cookies, CSRF tokens and the PKCE verifier: encrypt it at rest and
// keep it short-lived. It is not safe for concurrent use.
//
// Printing a challenge (String, GoString, and as a [slog.Value]) shows only the
// method, the destination and the creation time.
type MFAChallenge struct {
	// Method is the method the challenge is currently for.
	Method MFAMethod
	// Destination is the masked hint the server shows for the code's
	// destination, for example "******0100" for sms. It is empty for email
	// (the page shows no address) and authenticator_app.
	Destination string
	CreatedAt   time.Time
	// Offered lists the methods the account's method picker offered, in the
	// order authenticator_app, sms, email (the others are not supported by this
	// library and left out). It is nil until the picker has been seen: when the
	// server picks a default method the challenge page does not say what else
	// the account has, so callers must treat nil as "unknown". Once the picker
	// has been seen it is never nil: an empty, non-nil slice means the account
	// offers no supported method. It is set when the login lands on the picker
	// and by [SwitchMFAMethod], also when that fails because the account lacks
	// the method.
	Offered []MFAMethod

	cfg     Config
	cookies []wireCookie
	csrf    string // the verify form's hidden _csrf_token
	action  string // verify form action path
	mfaType string // verify form hidden "type" field

	// Resend form (sms and email); each form carries its own CSRF token.
	resendAction string            // action including its query, e.g. /login/two_factor_authentication/new?type=sms
	resendToken  string            // the resend form's own _csrf_token
	resendFields map[string]string // its other hidden fields (context=resend)

	verifier string
	state    string
}

// CanResend reports whether [ResendMFACode] can ask for another code: true
// for sms and email.
func (c *MFAChallenge) CanResend() bool {
	return c != nil && (c.Method == MFASMS || c.Method == MFAEmail)
}

// String describes the challenge without revealing cookies or tokens.
func (c MFAChallenge) String() string {
	s := "auth.MFAChallenge{method=" + string(c.Method)
	if c.Destination != "" {
		s += " destination=" + c.Destination
	}
	return s + " created=" + c.CreatedAt.Format(time.RFC3339) + "}"
}

// GoString implements [fmt.GoStringer] so that %#v does not dump secrets.
func (c MFAChallenge) GoString() string { return c.String() }

// LogValue implements [slog.LogValuer] and never reveals cookies or tokens.
func (c MFAChallenge) LogValue() slog.Value {
	attrs := []slog.Attr{slog.String("method", string(c.Method))}
	if c.Destination != "" {
		attrs = append(attrs, slog.String("destination", c.Destination))
	}
	return slog.GroupValue(append(attrs, slog.Time("created_at", c.CreatedAt))...)
}

type wireCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type challengeWire struct {
	Version      int               `json:"version"`
	Config       Config            `json:"config"`
	Cookies      []wireCookie      `json:"cookies"`
	CSRF         string            `json:"csrf"`
	Action       string            `json:"action"`
	MFAType      string            `json:"mfa_type"`
	ResendAction string            `json:"resend_action,omitzero"`
	ResendToken  string            `json:"resend_token,omitzero"`
	ResendFields map[string]string `json:"resend_fields,omitzero"`
	Verifier     string            `json:"verifier"`
	State        string            `json:"state"`
	Method       MFAMethod         `json:"method"`
	Destination  string            `json:"destination,omitzero"`
	Offered      []MFAMethod       `json:"offered,omitzero"`
	CreatedAt    time.Time         `json:"created_at"`
}

// MarshalBinary encodes the challenge as versioned JSON (version 3).
func (c *MFAChallenge) MarshalBinary() ([]byte, error) {
	return json.Marshal(challengeWire{
		Version: challengeV, Config: c.cfg, Cookies: c.cookies,
		CSRF: c.csrf, Action: c.action, MFAType: c.mfaType,
		ResendAction: c.resendAction, ResendToken: c.resendToken, ResendFields: c.resendFields,
		Verifier: c.verifier, State: c.state, Method: c.Method, Destination: c.Destination, Offered: c.Offered, CreatedAt: c.CreatedAt,
	})
}

// UnmarshalBinary decodes a challenge produced by MarshalBinary. Challenges
// of earlier versions (1 and 2) belong to the accounts login that ButterflyMX
// replaced in November 2026; their sessions are dead, so they are rejected.
func (c *MFAChallenge) UnmarshalBinary(data []byte) error {
	var w challengeWire
	if err := json.Unmarshal(data, &w); err != nil {
		// The decoder's own text can quote the input; the cause stays reachable.
		return newRedacted("auth: decode MFA challenge: invalid state", err)
	}
	if w.Version != challengeV {
		return fmt.Errorf("auth: unsupported MFA challenge version %d", w.Version)
	}
	*c = MFAChallenge{
		Method: w.Method, Destination: w.Destination, Offered: w.Offered, CreatedAt: w.CreatedAt, cfg: w.Config, cookies: w.Cookies,
		csrf: w.CSRF, action: w.Action, mfaType: w.MFAType,
		resendAction: w.ResendAction, resendToken: w.ResendToken, resendFields: w.ResendFields,
		verifier: w.Verifier, state: w.State,
	}
	return nil
}

// client builds a login client from the challenge's cookies. The challenge's
// own flow parameters win; the caller supplies transport and API settings.
func (c *MFAChallenge) client(cfg Config) (*loginClient, error) {
	merged := c.cfg
	merged.Now = c.clock(cfg)
	if cfg.HTTPClient != nil {
		merged.HTTPClient = cfg.HTTPClient
	}
	if cfg.APIURL != "" {
		merged.APIURL = cfg.APIURL
	}
	if cfg.UserAgent != "" {
		merged.UserAgent = cfg.UserAgent
	}
	if cfg.Device.Platform != "" {
		merged.Device = cfg.Device
	}
	return newLoginClient(merged.withDefaults(), c.cookies)
}

// ---- parsing the challenge page ----

var maskedDest = regexp.MustCompile(`\*{2,}\d{2,4}`)

type challengePage struct {
	csrf, action, mfaType     string
	resendAction, resendToken string
	resendFields              map[string]string
	destination               string
}

const mfaNewPath = mfaPath + "/new"

func (f *formInfo) path() string {
	if u, err := url.Parse(f.action); err == nil {
		return u.Path
	}
	return f.action
}

// resendForm finds the "Resend code" form: a post to .../new with context=resend.
func (p *pageInfo) resendForm() *formInfo {
	for i := range p.forms {
		f := &p.forms[i]
		if f.path() == mfaNewPath && f.inputs["context"] == "resend" && f.token() != "" {
			return f
		}
	}
	return nil
}

// pickerLinks returns the method picker's links by method (the href of each
// .../new?type=<method> anchor), and the number of picker-shaped links seen,
// including unknown methods.
func (p *pageInfo) pickerLinks() (map[MFAMethod]string, int) {
	out := map[MFAMethod]string{}
	n := 0
	for _, href := range p.links {
		u, err := url.Parse(href)
		if err != nil || u.Path != mfaNewPath || u.Query().Get("type") == "" {
			continue
		}
		n++
		m := MFAMethod(u.Query().Get("type"))
		if _, dup := out[m]; !dup {
			out[m] = href
		}
	}
	return out, n
}

func parseChallenge(l *loginClient, page *response, method MFAMethod) (*challengePage, error) {
	info, err := parsePage(page.body)
	if err != nil {
		return nil, l.flowChanged("two-factor page unparsable", page)
	}
	form := info.form(mfaPath)
	if form == nil || form.token() == "" {
		return nil, l.flowChanged("two-factor form not found", page)
	}
	cp := &challengePage{
		csrf:    form.token(),
		action:  mfaPath,
		mfaType: form.inputs["type"],
	}
	if cp.mfaType == "" {
		cp.mfaType = string(method)
	}
	if rf := info.resendForm(); rf != nil {
		cp.resendAction = rf.action
		cp.resendToken = rf.token()
		cp.resendFields = map[string]string{}
		for k, v := range rf.inputs {
			if k != csrfField {
				cp.resendFields[k] = v
			}
		}
	}
	if method == MFASMS {
		cp.destination = maskedDest.FindString(info.text)
	}
	return cp, nil
}

// apply replaces the page-derived fields of c and snapshots the cookies.
func (c *MFAChallenge) apply(cp *challengePage, method MFAMethod, l *loginClient) {
	c.Method = method
	c.Destination = cp.destination
	c.csrf, c.action, c.mfaType = cp.csrf, cp.action, cp.mfaType
	c.resendAction, c.resendToken, c.resendFields = cp.resendAction, cp.resendToken, cp.resendFields
	c.cookies = l.exportCookies()
}

// absorb reads the forms, tokens and hint from a challenge page for method and
// snapshots cookies. On error c is unchanged.
func (c *MFAChallenge) absorb(l *loginClient, page *response, method MFAMethod) error {
	cp, err := parseChallenge(l, page, method)
	if err != nil {
		return err
	}
	c.apply(cp, method, l)
	return nil
}

// ---- starting, switching and resending ----

// errPickerUnavailable marks a picker request that did not yield a usable 200
// picker page; StartLogin with [WithMFAMethod] falls back on it.
var errPickerUnavailable = errors.New("auth: method picker unavailable")

func (l *loginClient) startMFA(ctx context.Context, u *url.URL, verifier, state string, want MFAMethod) (*LoginResult, error) {
	def := MFAMethod(u.Query().Get("type"))
	if !def.valid() {
		return nil, fmt.Errorf("%w: the server's default method is %s", ErrMFAMethodUnsupported, l.name(string(def)))
	}
	c := &MFAChallenge{Method: def, CreatedAt: l.cfg.clock()(), cfg: l.cfg, verifier: verifier, state: state}
	switching := want != "" && want != def
	if switching {
		// Shortcut: skip the default challenge page, which may send a code.
		err := c.pick(ctx, l, want, true)
		if err == nil {
			return &LoginResult{Challenge: c}, nil
		}
		if !errors.Is(err, errPickerUnavailable) {
			return nil, err
		}
	}
	page, app, err := l.follow(ctx, u)
	if err != nil {
		return nil, err
	}
	if app != "" {
		return l.finish(ctx, app, verifier, state)
	}
	if page.status != http.StatusOK {
		return nil, l.flowChanged("two-factor page", page)
	}
	if err := c.absorb(l, page, def); err != nil {
		return nil, err
	}
	if switching {
		if err := c.pick(ctx, l, want, false); err != nil {
			return nil, err
		}
	}
	return &LoginResult{Challenge: c}, nil
}

// pick fetches the method picker and follows the link of method. With
// lenient set, a picker request that does not return a recognizable 200 picker
// page yields errPickerUnavailable instead of an error. On error c is
// unchanged, except that a recognized picker updates Offered.
func (c *MFAChallenge) pick(ctx context.Context, l *loginClient, method MFAMethod, lenient bool) error {
	pu, err := l.base.Parse(mfaPath)
	if err != nil {
		return ErrLoginFlowChanged
	}
	r, err := l.send(ctx, http.MethodGet, pu, nil)
	if err != nil {
		return err
	}
	return c.pickFrom(ctx, l, r, method, lenient)
}

// pickFrom follows the link of method on the picker page r.
func (c *MFAChallenge) pickFrom(ctx context.Context, l *loginClient, r *response, method MFAMethod, lenient bool) error {
	unavailable := func(what string) error {
		if lenient {
			return errPickerUnavailable
		}
		return l.flowChanged(what, r)
	}
	if r.status != http.StatusOK {
		return unavailable("method picker")
	}
	info, err := parsePage(r.body)
	if err != nil {
		return unavailable("method picker unparsable")
	}
	links, n := info.pickerLinks()
	if n == 0 {
		return unavailable("method picker not recognized")
	}
	c.Offered = offeredMethods(links)
	href := links[method]
	if href == "" {
		// A recognized picker without the method: the account does not have it
		// (an account without an authenticator app, say). That is an answer,
		// not a changed flow.
		return fmt.Errorf("%w: the account does not offer %q", ErrMFAMethodUnsupported, truncate(string(method), 40))
	}
	target, err := r.url.Parse(href)
	if err != nil {
		return l.flowChanged("bad method picker link", r)
	}
	// Following the link is the choice; for sms and email it is assumed to
	// send the code (the old server did; not verified on the new one).
	resp, err := l.send(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	if resp.status != http.StatusOK {
		return l.flowChanged("unrecognized response to method choice", resp)
	}
	return c.absorb(l, resp, method)
}

// offeredMethods lists the supported methods of a picker in the order
// authenticator_app, sms, email.
func offeredMethods(links map[MFAMethod]string) []MFAMethod {
	// Never nil: nil means "the picker has not been seen".
	out := []MFAMethod{}
	for _, m := range []MFAMethod{MFAAuthenticatorApp, MFASMS, MFAEmail} {
		if links[m] != "" {
			out = append(out, m)
		}
	}
	return out
}

// pickerPreference orders the methods to take when the server offers a choice
// and the caller expressed none: the authenticator app first, because choosing
// it sends nothing, then email, then sms.
var pickerPreference = []MFAMethod{MFAAuthenticatorApp, MFAEmail, MFASMS}

// startMFAPicker starts the challenge when the server lands on the method
// picker instead of a default method's challenge page. It takes want, or else
// the first offered method of [pickerPreference].
func (l *loginClient) startMFAPicker(ctx context.Context, u *url.URL, verifier, state string, want MFAMethod) (*LoginResult, error) {
	page, app, err := l.follow(ctx, u)
	if err != nil {
		return nil, err
	}
	if app != "" {
		return l.finish(ctx, app, verifier, state)
	}
	if page.status != http.StatusOK {
		return nil, l.flowChanged("method picker", page)
	}
	info, err := parsePage(page.body)
	if err != nil {
		return nil, l.flowChanged("method picker unparsable", page)
	}
	links, n := info.pickerLinks()
	if n == 0 {
		return nil, l.flowChanged("method picker not recognized", page)
	}
	method := want
	if method == "" {
		for _, m := range pickerPreference {
			if links[m] != "" {
				method = m
				break
			}
		}
		if method == "" {
			return nil, fmt.Errorf("%w: the server offers no supported method", ErrMFAMethodUnsupported)
		}
	}
	c := &MFAChallenge{Method: method, CreatedAt: l.cfg.clock()(), cfg: l.cfg, verifier: verifier, state: state}
	if err := c.pickFrom(ctx, l, page, method, false); err != nil {
		return nil, err
	}
	return &LoginResult{Challenge: c}, nil
}

// clock returns the clock for c: cfg.Now, else the clock c was created with,
// else [time.Now].
func (c *MFAChallenge) clock(cfg Config) func() time.Time {
	if cfg.Now != nil {
		return cfg.Now
	}
	return c.cfg.clock()
}

func (c *MFAChallenge) usable(cfg Config, method MFAMethod, check bool) error {
	if c == nil {
		return errors.New("auth: nil MFA challenge")
	}
	if check && !method.valid() {
		return fmt.Errorf("%w: %q", ErrMFAMethodUnsupported, string(method))
	}
	if c.clock(cfg)().Sub(c.CreatedAt) > MFAChallengeTTL {
		return ErrMFAExpired
	}
	return nil
}

// SwitchMFAMethod switches the pending login to another second factor
// ("Verify another way"). It fetches the method picker, follows the chosen
// method's link and takes the challenge page that comes back. For sms and
// email this is assumed to make the server send a code (as it did on the old
// server).
//
// c is updated in place (Method, Destination, tokens and cookies); marshal it
// again afterwards. Choosing the current method is allowed and re-sends the
// code for sms and email. On error c keeps its method, destination and forms;
// what the server answered is still taken over: the session cookies, the CSRF
// tokens (the server rotates its double-submit cookie, and the form tokens
// follow it) and, once the picker was read, Offered. Marshal c again after an
// error too.
//
// It returns [ErrMFAExpired] for an old challenge, [ErrMFAMethodUnsupported]
// for a method other than authenticator_app, sms and email or one the
// account does not offer (the picker has no link for it), and
// [ErrLoginFlowChanged] when the picker is not recognized.
func SwitchMFAMethod(ctx context.Context, cfg Config, c *MFAChallenge, method MFAMethod) error {
	if err := c.usable(cfg, method, true); err != nil {
		return err
	}
	l, err := c.client(cfg)
	if err != nil {
		return err
	}
	err = c.pick(ctx, l, method, false)
	c.keepSession(l)
	return err
}

// keepSession stores the latest session cookies after a request that failed
// without taking over a new page, so the challenge stays usable. The server
// double-submits its CSRF token (the _csrf_token cookie must equal the form
// field), and a response may have rotated the cookie, so the challenge's form
// tokens follow it: a stale form token next to a fresh cookie would be rejected.
func (c *MFAChallenge) keepSession(l *loginClient) {
	c.cookies = l.exportCookies()
	for _, ck := range c.cookies {
		if ck.Name == csrfField && ck.Value != "" {
			c.csrf = ck.Value
			if c.resendToken != "" {
				c.resendToken = ck.Value
			}
		}
	}
}

// ResendMFACode asks for another code for sms and email challenges: it posts
// the challenge page's "Resend code" form (context=resend, that form's own
// _csrf_token) and takes the challenge page that comes back, following a
// redirect if the server answers with one. Earlier codes are assumed to keep
// working, as they did on the old server (not verified on the current one).
// c is updated in place (including fresh tokens); marshal it again
// afterwards. On error c keeps its method, destination and forms, and takes
// over the session cookies and CSRF tokens the server last issued, as
// [SwitchMFAMethod] does; marshal it again then too.
//
// authenticator_app returns [ErrMFAResendUnsupported]. If c has no resend form
// (the page had none), the code is re-sent by choosing the current method
// again, as [SwitchMFAMethod] does.
func ResendMFACode(ctx context.Context, cfg Config, c *MFAChallenge) (err error) {
	if err := c.usable(cfg, "", false); err != nil {
		return err
	}
	if !c.CanResend() {
		if !c.Method.valid() {
			return fmt.Errorf("%w: %q", ErrMFAMethodUnsupported, string(c.Method))
		}
		return ErrMFAResendUnsupported
	}
	l, err := c.client(cfg)
	if err != nil {
		return err
	}
	// Whatever goes wrong after this point, keep the session cookies the
	// server has issued so far.
	defer func() {
		if err != nil {
			c.keepSession(l)
		}
	}()
	if c.resendAction == "" || c.resendToken == "" {
		err = c.pick(ctx, l, c.Method, false)
		c.keepSession(l)
		return err
	}
	target, err := l.base.Parse(c.resendAction)
	if err != nil {
		return ErrLoginFlowChanged
	}
	form := url.Values{}
	for k, v := range c.resendFields {
		form.Set(k, v)
	}
	form.Set("context", "resend")
	form.Set(csrfField, c.resendToken)
	resp, err := l.send(ctx, http.MethodPost, target, form)
	if err != nil {
		return err
	}
	if isRedirect(resp.status) {
		next, app, nerr := l.nextLocation(resp)
		if nerr != nil || app != "" {
			c.keepSession(l)
			return l.flowChanged("unrecognized response to resend", resp)
		}
		page, app, ferr := l.follow(ctx, next)
		if ferr != nil {
			c.keepSession(l)
			return ferr
		}
		if app != "" {
			c.keepSession(l)
			return l.flowChanged("unrecognized response to resend", resp)
		}
		resp = page
	}
	if resp.status != http.StatusOK {
		c.keepSession(l)
		return l.flowChanged("unrecognized response to resend", resp)
	}
	return c.absorb(l, resp, c.Method)
}
