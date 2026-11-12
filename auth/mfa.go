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

const challengeV = 2

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

	cfg      Config
	cookies  []wireCookie
	csrfMeta string // <meta name="csrf-token">, sent as X-CSRF-Token on the verify POST only
	csrfForm string // the verify form's hidden authenticity_token, sent in the body
	action   string // verify form action path
	mfaType  string // verify form hidden "type" field

	// Resend form (sms and email); CSRF tokens are per form.
	resendAction string            // action including its query, e.g. /sessions/two_factor_authentication/new?type=sms
	resendToken  string            // the resend form's own authenticity_token
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
	CSRFMeta     string            `json:"csrf_meta"`
	CSRFForm     string            `json:"csrf_form"`
	Action       string            `json:"action"`
	MFAType      string            `json:"mfa_type"`
	ResendAction string            `json:"resend_action,omitzero"`
	ResendToken  string            `json:"resend_token,omitzero"`
	ResendFields map[string]string `json:"resend_fields,omitzero"`
	Verifier     string            `json:"verifier"`
	State        string            `json:"state"`
	Method       MFAMethod         `json:"method"`
	Destination  string            `json:"destination,omitzero"`
	CreatedAt    time.Time         `json:"created_at"`
}

// MarshalBinary encodes the challenge as versioned JSON (version 2).
func (c *MFAChallenge) MarshalBinary() ([]byte, error) {
	return json.Marshal(challengeWire{
		Version: challengeV, Config: c.cfg, Cookies: c.cookies,
		CSRFMeta: c.csrfMeta, CSRFForm: c.csrfForm, Action: c.action, MFAType: c.mfaType,
		ResendAction: c.resendAction, ResendToken: c.resendToken, ResendFields: c.resendFields,
		Verifier: c.verifier, State: c.state, Method: c.Method, Destination: c.Destination, CreatedAt: c.CreatedAt,
	})
}

// UnmarshalBinary decodes a challenge produced by MarshalBinary. Version 1
// blobs (written before sms and email were supported) are accepted; they have
// no resend form and no destination.
func (c *MFAChallenge) UnmarshalBinary(data []byte) error {
	var w challengeWire
	if err := json.Unmarshal(data, &w); err != nil {
		return fmt.Errorf("auth: decode MFA challenge: %w", err)
	}
	if w.Version != challengeV && w.Version != 1 {
		return fmt.Errorf("auth: unsupported MFA challenge version %d", w.Version)
	}
	*c = MFAChallenge{
		Method: w.Method, Destination: w.Destination, CreatedAt: w.CreatedAt, cfg: w.Config, cookies: w.Cookies,
		csrfMeta: w.CSRFMeta, csrfForm: w.CSRFForm, action: w.Action, mfaType: w.MFAType,
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
	csrfMeta, csrfForm, action, mfaType string
	resendAction, resendToken           string
	resendFields                        map[string]string
	destination                         string
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
		if f.path() == mfaNewPath && f.inputs["context"] == "resend" && f.inputs["authenticity_token"] != "" {
			return f
		}
	}
	return nil
}

// pickerForms returns the method picker's one-button forms by method, and the
// number of picker-shaped forms seen (including unknown methods).
func (p *pageInfo) pickerForms() (map[MFAMethod]*formInfo, int) {
	out := map[MFAMethod]*formInfo{}
	n := 0
	for i := range p.forms {
		f := &p.forms[i]
		if f.path() != mfaNewPath {
			continue
		}
		if _, isResend := f.inputs["context"]; isResend {
			continue
		}
		u, err := url.Parse(f.action)
		if err != nil || u.Query().Get("type") == "" {
			continue
		}
		n++
		if f.inputs["authenticity_token"] != "" {
			out[MFAMethod(u.Query().Get("type"))] = f
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
	if form == nil || info.csrfMeta == "" || form.inputs["authenticity_token"] == "" {
		return nil, l.flowChanged("two-factor form not found", page)
	}
	cp := &challengePage{
		csrfMeta: info.csrfMeta,
		csrfForm: form.inputs["authenticity_token"],
		action:   mfaPath,
		mfaType:  form.inputs["type"],
	}
	if cp.mfaType == "" {
		cp.mfaType = string(method)
	}
	if rf := info.resendForm(); rf != nil {
		cp.resendAction = rf.action
		cp.resendToken = rf.inputs["authenticity_token"]
		cp.resendFields = map[string]string{}
		for k, v := range rf.inputs {
			if k != "authenticity_token" {
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
	c.csrfMeta, c.csrfForm, c.action, c.mfaType = cp.csrfMeta, cp.csrfForm, cp.action, cp.mfaType
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
		return nil, fmt.Errorf("%w: %q", ErrMFAMethodUnsupported, truncate(string(def), 40))
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

// pick fetches the method picker and posts the form of method. With lenient
// set, a picker request that does not return a recognizable 200 picker page
// yields errPickerUnavailable instead of an error. On error c is unchanged.
func (c *MFAChallenge) pick(ctx context.Context, l *loginClient, method MFAMethod, lenient bool) error {
	pu, err := l.base.Parse(mfaPath)
	if err != nil {
		return ErrLoginFlowChanged
	}
	r, err := l.send(ctx, http.MethodGet, pu, nil, "")
	if err != nil {
		return err
	}
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
	forms, n := info.pickerForms()
	if n == 0 {
		return unavailable("method picker not recognized")
	}
	f := forms[method]
	if f == nil {
		return l.flowChanged("method picker has no form for "+truncate(string(method), 40), r)
	}
	target, err := r.url.Parse(f.action)
	if err != nil {
		return l.flowChanged("bad method picker form action", r)
	}
	// Plain form post with the chosen form's own token and any other hidden inputs.
	form := url.Values{}
	for k, v := range f.inputs {
		form.Set(k, v)
	}
	resp, err := l.sendPlainForm(ctx, target, form)
	if err != nil {
		return err
	}
	if resp.status != http.StatusOK {
		return l.flowChanged("unrecognized response to method choice", resp)
	}
	return c.absorb(l, resp, method)
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
// ("Verify another way"). It fetches the method picker, posts the chosen
// method's own form (with that form's authenticity_token, no X-CSRF-Token
// header and a browser-style Accept, as the app does) and takes the returned
// challenge page. For sms and email this makes the server send a code.
//
// c is updated in place (Method, Destination, tokens and cookies); marshal it
// again afterwards. Choosing the current method is allowed and re-sends the
// code for sms and email. On error c keeps its method, forms and tokens (only
// its session cookies are refreshed).
//
// It returns [ErrMFAExpired] for an old challenge, [ErrMFAMethodUnsupported]
// for a method other than authenticator_app, sms and email, and
// [ErrLoginFlowChanged] when the picker has no form for the method.
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
// without changing the challenge's tokens, so the challenge stays usable.
func (c *MFAChallenge) keepSession(l *loginClient) { c.cookies = l.exportCookies() }

// ResendMFACode asks for another code for sms and email challenges: it posts
// the challenge page's "Resend code" form (context=resend, that form's own
// authenticity_token, no X-CSRF-Token header) and takes the returned page.
// Earlier codes keep working, so callers need not discard
// them. c is updated in place (including fresh tokens); marshal it again
// afterwards. On error c keeps its forms and tokens (only its session cookies
// are refreshed).
//
// authenticator_app returns [ErrMFAResendUnsupported]. If c has no resend form
// (it was restored from a version 1 blob, or the page had none), the code is
// re-sent by choosing the current method again, as [SwitchMFAMethod] does.
func ResendMFACode(ctx context.Context, cfg Config, c *MFAChallenge) error {
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
	form.Set("authenticity_token", c.resendToken)
	resp, err := l.sendPlainForm(ctx, target, form)
	if err != nil {
		return err
	}
	if resp.status != http.StatusOK {
		c.keepSession(l)
		return l.flowChanged("unrecognized response to resend", resp)
	}
	return c.absorb(l, resp, c.Method)
}
