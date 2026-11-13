package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// MFAChallengeTTL is how long an [MFAChallenge] stays valid. Variable for tests.
var MFAChallengeTTL = 10 * time.Minute

const (
	maxHops      = 10
	mfaPath      = "/login/two_factor_authentication"
	loginPath    = "/login"
	loginNewPath = "/login/new"
	authorizeP   = "/oauth/authorize"
	htmlAccept   = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

	// csrfField is the hidden input every form carries. The server sets the
	// same value as the _csrf_token cookie (double submit), so the cookie jar
	// and the form must travel together.
	csrfField = "_csrf_token"
)

// invalidCredentials matches the message the login page shows after a
// rejected email or password.
var invalidCredentials = regexp.MustCompile(`(?i)invalid email or password`)

// LoginResult is the outcome of [StartLogin]; exactly one field is non-nil.
type LoginResult struct {
	Token     *Token
	Challenge *MFAChallenge
}

// loginClient wraps an http.Client with its own jar and no auto-redirects.
type loginClient struct {
	cfg     Config
	base    *url.URL
	hc      *http.Client
	jar     *cookiejar.Jar
	secrets []string // redacted from error text
}

func newLoginClient(cfg Config, cookies []wireCookie) (*loginClient, error) {
	base, err := url.Parse(cfg.AccountsURL)
	if err != nil || base.Host == "" {
		return nil, fmt.Errorf("auth: invalid AccountsURL %q", cfg.AccountsURL)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	if len(cookies) > 0 {
		hc := make([]*http.Cookie, len(cookies))
		for i, c := range cookies {
			hc[i] = &http.Cookie{Name: c.Name, Value: c.Value, Path: "/"}
		}
		jar.SetCookies(base, hc)
	}
	b := cfg.HTTPClient
	if b == nil {
		b = http.DefaultClient
	}
	return &loginClient{cfg: cfg, base: base, jar: jar, hc: &http.Client{
		Transport: b.Transport,
		Timeout:   b.Timeout,
		Jar:       jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}, nil
}

func (l *loginClient) exportCookies() []wireCookie {
	var out []wireCookie
	for _, c := range l.jar.Cookies(l.base) {
		out = append(out, wireCookie{Name: c.Name, Value: c.Value})
	}
	return out
}

type response struct {
	status int
	header http.Header
	body   string
	url    *url.URL
}

// send makes one request the way the browser does: a navigation GET, or a
// plain urlencoded form POST. There are no CSRF headers; the token travels in
// the form body (and in the cookie jar).
func (l *loginClient) send(ctx context.Context, method string, u *url.URL, form url.Values) (*response, error) {
	if u.Host != l.base.Host || u.Scheme != l.base.Scheme {
		return nil, fmt.Errorf("%w: unexpected origin %q", ErrLoginFlowChanged, truncate(l.redact(u.Scheme+"://"+u.Host), 80))
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, l.transportErr(u, err)
	}
	req.Header.Set("User-Agent", l.cfg.WebUserAgent)
	req.Header.Set("Accept", htmlAccept)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", l.base.Scheme+"://"+l.base.Host)
	}
	resp, err := l.hc.Do(req)
	if err != nil {
		return nil, l.transportErr(u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, l.transportErr(u, err)
	}
	return &response{status: resp.StatusCode, header: resp.Header, body: string(b), url: u}, nil
}

// transportErr is what every failure of a request in the login flow becomes.
// net/http's error text quotes the URL (which came from the server's pages and
// redirects, with its query) and, for a malformed response, what the server
// sent; both are redacted, and the URL is shown without query, userinfo and
// fragment. The original cause stays reachable for errors.Is and errors.As,
// and a network cause keeps the net.Error methods.
func (l *loginClient) transportErr(u *url.URL, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		shown := *u
		shown.RawQuery, shown.Fragment, shown.User = "", "", nil
		return &redactedURLError{redactedError{
			msg: fmt.Sprintf("%s %s: %s", ue.Op, truncate(l.redact(shown.String()), 120), truncate(l.redact(ue.Err.Error()), 200)),
			err: ue.Err,
		}}
	}
	return newRedacted(truncate(l.redact(err.Error()), 300), err)
}

func isRedirect(status int) bool { return status >= 300 && status < 400 }

// follow performs a GET and manually follows redirects (max maxHops) until a
// non-redirect page, or the hand-off to the app, whose raw URL is returned as
// appRedirect. The hand-off is either a Location starting with the app
// redirect URI or, as the server does now, a 200 "Returning to app" page that
// links to it.
func (l *loginClient) follow(ctx context.Context, u *url.URL) (page *response, appRedirect string, err error) {
	for range maxHops {
		r, err := l.send(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, "", err
		}
		if !isRedirect(r.status) {
			if app := l.appLink(r); app != "" {
				return nil, app, nil
			}
			return r, "", nil
		}
		next, app, err := l.nextLocation(r)
		if err != nil {
			return nil, "", err
		}
		if app != "" {
			return nil, app, nil
		}
		u = next
	}
	return nil, "", fmt.Errorf("%w: too many redirects", ErrLoginFlowChanged)
}

// appLink returns the app redirect URL a 200 page links to ("Returning to
// app…" with a "Tap here if nothing happens" link), or "".
func (l *loginClient) appLink(r *response) string {
	if r.status != http.StatusOK {
		return ""
	}
	info, err := parsePage(r.body)
	if err != nil {
		return ""
	}
	for _, href := range info.links {
		if l.cfg.isAppRedirect(href) {
			return href
		}
	}
	return ""
}

// nextLocation resolves a redirect's Location. app is non-empty when it
// points at the app redirect URI.
func (l *loginClient) nextLocation(r *response) (next *url.URL, app string, err error) {
	loc := r.header.Get("Location")
	if loc == "" {
		return nil, "", fmt.Errorf("%w: redirect without Location", ErrLoginFlowChanged)
	}
	if l.cfg.isAppRedirect(loc) {
		return nil, loc, nil
	}
	next, err = r.url.Parse(loc)
	if err != nil {
		return nil, "", fmt.Errorf("%w: bad Location", ErrLoginFlowChanged)
	}
	return next, "", nil
}

// ---- HTML parsing ----

type formInfo struct {
	action string
	inputs map[string]string
}

type pageInfo struct {
	forms []formInfo
	links []string // href of every <a>
	text  string   // visible text, whitespace-normalized
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

// isInert reports whether the text inside n is not shown to the user:
// templates, noscript fallbacks and elements hidden by attribute or style.
// Such text can hold embedded application data, so diagnostics leave it out.
func isInert(n *html.Node) bool {
	if n.Data == "template" || n.Data == "noscript" {
		return true
	}
	for _, a := range n.Attr {
		switch a.Key {
		case "hidden":
			return true
		case "style":
			if strings.Contains(strings.ReplaceAll(strings.ToLower(a.Val), " ", ""), "display:none") {
				return true
			}
		}
	}
	return false
}

func parsePage(body string) (*pageInfo, error) {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	p := &pageInfo{}
	var text strings.Builder
	var cur *formInfo
	inert := 0 // depth inside content the user does not see
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode && inert == 0 && n.Parent != nil && n.Parent.Data != "script" && n.Parent.Data != "style" {
			text.WriteString(n.Data)
			text.WriteByte(' ')
		}
		if n.Type == html.ElementNode {
			if isInert(n) {
				inert++
				defer func() { inert-- }()
			}
			switch n.Data {
			case "a":
				if href := attr(n, "href"); href != "" {
					p.links = append(p.links, href)
				}
			case "form":
				p.forms = append(p.forms, formInfo{action: attr(n, "action"), inputs: map[string]string{}})
				cur = &p.forms[len(p.forms)-1]
				defer func() { cur = nil }()
			case "input":
				if cur != nil {
					if name := attr(n, "name"); name != "" {
						cur.inputs[name] = attr(n, "value")
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	p.text = strings.Join(strings.Fields(text.String()), " ")
	return p, nil
}

// token is the form's CSRF token.
func (f *formInfo) token() string { return f.inputs[csrfField] }

func (p *pageInfo) form(path string) *formInfo {
	for i := range p.forms {
		a := p.forms[i].action
		if u, err := url.Parse(a); err == nil {
			a = u.Path
		}
		if a == path {
			return &p.forms[i]
		}
	}
	return nil
}

// ---- flow ----

// opaqueRun matches long token-like runs (CSRF tokens are 86 base64url characters).
var opaqueRun = regexp.MustCompile(`[A-Za-z0-9_-]{40,}`)

// redact removes the submitted secrets (also in URL-encoded form) and long
// opaque values (CSRF tokens, OAuth codes) from text taken from a response.
func (l *loginClient) redact(text string) string {
	for _, sec := range l.secrets {
		if sec == "" {
			continue
		}
		for _, v := range []string{sec, url.QueryEscape(sec), url.PathEscape(sec)} {
			text = strings.ReplaceAll(text, v, "[redacted]")
		}
	}
	// Whole values go first: masking digits or phone numbers inside a long hex
	// value would split it and leave fragments, and so would masking a long
	// token inside an email address before the address is recognized.
	text = emailAddr.ReplaceAllString(text, "[email]")
	text = opaqueRun.ReplaceAllString(text, "[redacted]")
	text = phoneNumber.ReplaceAllString(text, "[phone]")
	return digitRun.ReplaceAllString(text, "[number]")
}

var (
	emailAddr = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	// phoneNumber covers 10-digit numbers written with separators, such as
	// (555) 555-0100 and +1 555-555-0100; unseparated ones fall to digitRun.
	phoneNumber = regexp.MustCompile(`(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}`)
	// digitRun covers MFA codes and phone numbers; the masked hint of an SMS
	// destination ("******9736") has four digits and stays readable.
	digitRun = regexp.MustCompile(`\d{5,}`)
)

// redactedError shows a redacted message and keeps the original error for
// errors.Is and errors.As.
type redactedError struct {
	msg string
	err error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.err }

// redactedURLError replaces a *url.Error: like it, it is a net.Error whose
// Timeout and Temporary answer for the cause, so callers that classify a
// failed request that way (timeouts, cancellations, refused connections) see
// the same thing.
type redactedURLError struct{ redactedError }

func (e *redactedURLError) Timeout() bool {
	var t interface{ Timeout() bool }
	return errors.As(e.err, &t) && t.Timeout()
}

func (e *redactedURLError) Temporary() bool {
	var t interface{ Temporary() bool }
	return errors.As(e.err, &t) && t.Temporary()
}

func newRedacted(msg string, err error) error { return &redactedError{msg: msg, err: err} }

// redactErr is what the OAuth leg of a headless login (code exchange, region
// discovery, denizen login) reports. These endpoints are called with the
// authorization code, tokens and, at that point, a login that has just used the
// user's password or MFA code, and an error that reflects server text cannot
// be made safe by pattern matching (a server can echo a secret JSON-escaped,
// split, or as a token this code never saw). So no server text is kept: an
// *Error is copied without Description and Body (Op, Status and the allowlisted
// Code stay), and any other failure becomes a message naming only its class.
// The original error stays reachable through errors.Is and errors.As.
func (l *loginClient) redactErr(err error) error {
	if err == nil {
		return nil
	}
	var ae *Error
	if errors.As(err, &ae) {
		cp := *ae
		cp.Description, cp.Body = "", ""
		return &cp
	}
	msg := "auth: request to ButterflyMX failed: " + errorClass(err)
	var ne net.Error
	if errors.As(err, &ne) {
		return &redactedURLError{redactedError{msg: msg, err: err}}
	}
	return newRedacted(msg, err)
}

// errorClass names the kind of a transport failure without quoting it.
func errorClass(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timed out"
	case errors.As(err, &ne):
		return "network error"
	}
	return "unexpected response"
}

var safeName = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)

// name returns a server-supplied identifier (an MFA method name) for an error
// message: only if it looks like one, and never a submitted secret.
func (l *loginClient) name(s string) string {
	if !safeName.MatchString(s) {
		return "(unrecognized)"
	}
	return l.redact(s)
}

func (l *loginClient) flowChanged(what string, r *response) error {
	// Describe the page by its visible text and form targets only: the raw
	// body is scripts, styles and embedded application state, which say nothing
	// about what changed and can hold private data. Form actions are reduced to
	// their path: queries can carry anything.
	body := "(unparsable page)"
	if info, err := parsePage(r.body); err == nil {
		body = info.text
		if body == "" {
			body = "(no visible text)"
		}
		var actions []string
		for _, f := range info.forms {
			actions = append(actions, formTarget(f.action))
		}
		if len(actions) > 0 {
			body = "forms: " + strings.Join(actions, ", ") + "; " + body
		}
	}
	// "what" can embed server-controlled text (a redirect path), so it is
	// redacted like the body.
	return fmt.Errorf("%w: %s (HTTP %d): %s", ErrLoginFlowChanged, l.redact(what), r.status,
		truncate(strings.Join(strings.Fields(l.redact(body)), " "), 300))
}

// formTarget is a form action reduced to its path; one that does not parse is
// not shown (the query of a malformed action is not to be trusted either).
func formTarget(action string) string {
	u, err := url.Parse(action)
	if err != nil {
		return "(invalid action)"
	}
	return u.Path
}

// LoginOption customizes [StartLogin].
type LoginOption func(*loginOptions)

type loginOptions struct {
	method MFAMethod
}

// WithMFAMethod asks for the second factor m instead of the one the server
// picks. The server's default is the method of the account's last successful
// login, and loading its challenge page can itself send a text or an email.
//
// When the default method differs from m, StartLogin goes straight to the
// method picker ("Verify another way") and chooses m, without loading the
// default challenge page, which would itself send a code by SMS or email (the
// old server texted or emailed on loading that page; the current one is
// assumed to). Choosing sms or email in the picker is assumed to send the
// code for m.
//
// This shortcut is unverified against production. If the picker request does
// not return a 200 picker page (for example it redirects back to the login
// page, or returns an unrecognized page), StartLogin falls back to what the
// app does: it loads the default challenge page, then uses the picker from
// there. Any later failure is returned as an error. When the default already
// equals m the option has no effect. A method other than authenticator_app,
// sms and email makes StartLogin fail with [ErrMFAMethodUnsupported] before any
// request.
func WithMFAMethod(m MFAMethod) LoginOption {
	return func(o *loginOptions) { o.method = m }
}

// StartLogin begins a headless login with email and password (spec 3.2). The
// password is used once and never stored. If the account requires two-factor
// authentication, the result carries a challenge for [CompleteLogin]; its
// Method is the server's default method (any of authenticator_app, sms and
// email, whose code the server has been asked to send, as the app does) or the
// one requested with [WithMFAMethod]. When the server has no default and lands
// on the method picker, the requested method is chosen, or else the first
// offered of authenticator_app, email and sms (the app sends nothing). Use
// [SwitchMFAMethod] and [ResendMFACode] to change method or request another
// code.
func StartLogin(ctx context.Context, cfg Config, email, password string, opts ...LoginOption) (*LoginResult, error) {
	var o loginOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	if o.method != "" && !o.method.valid() {
		return nil, fmt.Errorf("%w: %q", ErrMFAMethodUnsupported, string(o.method))
	}
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	verifier, err := randomString()
	if err != nil {
		return nil, err
	}
	state, err := randomString()
	if err != nil {
		return nil, err
	}
	nonce, err := randomString()
	if err != nil {
		return nil, err
	}
	l, err := newLoginClient(cfg, nil)
	if err != nil {
		return nil, err
	}
	l.secrets = []string{email, password}

	start, _ := url.Parse(authorizeURL(cfg, pkceChallenge(verifier), state, nonce))
	page, app, err := l.follow(ctx, start)
	if err != nil {
		return nil, err
	}
	if app != "" { // session already authorized
		return l.finish(ctx, app, verifier, state)
	}
	if page.status != http.StatusOK {
		return nil, l.flowChanged("login page", page)
	}
	info, err := parsePage(page.body)
	if err != nil {
		return nil, l.flowChanged("login page unparsable", page)
	}
	form := info.form(loginPath)
	if form == nil || form.token() == "" {
		return nil, l.flowChanged("login form not found", page)
	}
	if _, ok := form.inputs["email"]; !ok {
		return nil, l.flowChanged("login form has no email field", page)
	}
	if _, ok := form.inputs["password"]; !ok {
		return nil, l.flowChanged("login form has no password field", page)
	}
	target, err := page.url.Parse(form.action)
	if err != nil {
		return nil, l.flowChanged("bad login form action", page)
	}
	// Post the form as the browser would: its hidden inputs (the CSRF token and
	// return_to) as served, plus the credentials and the submit button.
	values := url.Values{}
	for k, v := range form.inputs {
		values.Set(k, v)
	}
	values.Set("email", email)
	values.Set("password", password)
	values.Set("commit", "Sign in with email")
	resp, err := l.send(ctx, http.MethodPost, target, values)
	if err != nil {
		return nil, err
	}

	// Classify.
	if isRedirect(resp.status) {
		next, app, err := l.nextLocation(resp)
		if err != nil {
			return nil, err
		}
		switch {
		case app != "":
			return l.finish(ctx, app, verifier, state)
		case next.Path == mfaPath+"/new":
			return l.startMFA(ctx, next, verifier, state, o.method)
		case next.Path == mfaPath:
			// No default method: the server lands on the method picker.
			return l.startMFAPicker(ctx, next, verifier, state, o.method)
		case next.Path == authorizeP:
			return l.finish(ctx, next.String(), verifier, state)
		case next.Path == loginNewPath || next.Path == loginPath:
			return nil, l.loginRejected(ctx, next)
		}
		return nil, l.flowChanged("unexpected redirect "+next.Path, resp)
	}
	if app := l.appLink(resp); app != "" {
		return l.finish(ctx, app, verifier, state)
	}
	if isInvalidCredentialsPage(resp) {
		return nil, ErrInvalidCredentials
	}
	return nil, l.flowChanged("unrecognized response to login", resp)
}

// loginRejected follows the redirect back to the login page that a failed
// sign-in gets. The page then shows "Invalid email or password"; anything else
// (the page also appears for a bad CSRF token, say) is a changed flow.
func (l *loginClient) loginRejected(ctx context.Context, next *url.URL) error {
	page, app, err := l.follow(ctx, next)
	if err != nil {
		return err
	}
	if app != "" {
		return fmt.Errorf("%w: sign-in was sent back to the login page, which handed off to the app", ErrLoginFlowChanged)
	}
	if isInvalidCredentialsPage(page) {
		return ErrInvalidCredentials
	}
	return l.flowChanged("login sent back to the form without a known error", page)
}

// isInvalidCredentialsPage reports whether r is the login form re-rendered
// with the "Invalid email or password" error.
func isInvalidCredentialsPage(r *response) bool {
	if r.status != http.StatusOK && r.status != http.StatusUnprocessableEntity {
		return false
	}
	info, err := parsePage(r.body)
	if err != nil {
		return false
	}
	f := info.form(loginPath)
	if f == nil {
		return false
	}
	_, hasEmail := f.inputs["email"]
	return hasEmail && invalidCredentials.MatchString(info.text)
}

// finish follows the authorize redirect chain to the app redirect and
// completes the token exchange.
func (l *loginClient) finish(ctx context.Context, location, verifier, state string) (*LoginResult, error) {
	tok, err := l.finishToken(ctx, location, verifier, state)
	if err != nil {
		return nil, err
	}
	return &LoginResult{Token: tok}, nil
}

func (l *loginClient) finishToken(ctx context.Context, location, verifier, state string) (*Token, error) {
	app := ""
	if l.cfg.isAppRedirect(location) {
		app = location
	} else {
		u, err := l.base.Parse(location)
		if err != nil {
			return nil, fmt.Errorf("%w: bad authorize location", ErrLoginFlowChanged)
		}
		page, a, err := l.follow(ctx, u)
		if err != nil {
			return nil, err
		}
		if a == "" {
			return nil, l.flowChanged("authorize did not redirect to the app", page)
		}
		app = a
	}
	code, err := codeFromRedirect(l.cfg, app, state)
	if err != nil {
		return nil, err
	}
	tok, err := completeFromCode(withSecrets(ctx, l.secrets), l.cfg, code, verifier)
	return tok, l.redactErr(err)
}

// CompleteLogin submits the two-factor code and finishes the login. The
// verify form's type comes from the challenge page, so it works for every
// method. A wrong code returns [ErrInvalidMFACode] and updates c in place (the
// fresh verify, meta and resend CSRF tokens, and cookies) so it can be
// re-marshaled and retried. Challenges older than
// [MFAChallengeTTL] return [ErrMFAExpired].
func CompleteLogin(ctx context.Context, cfg Config, c *MFAChallenge, code string) (tok *Token, err error) {
	if c == nil {
		return nil, errors.New("auth: nil MFA challenge")
	}
	if !c.Method.valid() {
		return nil, fmt.Errorf("%w: %q", ErrMFAMethodUnsupported, string(c.Method))
	}
	if c.clock(cfg)().Sub(c.CreatedAt) > MFAChallengeTTL {
		return nil, ErrMFAExpired
	}
	l, err := c.client(cfg)
	if err != nil {
		return nil, err
	}
	l.secrets = []string{code}
	// An error leaves c usable for a retry: keep the cookies the server has
	// issued so far (a wrong code has already replaced them with the new page's).
	defer func() {
		if err != nil {
			c.keepSession(l)
		}
	}()
	target, err := l.base.Parse(c.action)
	if err != nil {
		return nil, ErrLoginFlowChanged
	}
	resp, err := l.send(ctx, http.MethodPost, target, url.Values{
		csrfField: {c.csrf},
		"type":    {c.mfaType},
		"code":    {code},
	})
	if err != nil {
		return nil, err
	}

	// Success redirects to /oauth/authorize (or straight to the app); a code
	// the server does not accept puts the challenge page back in front of us.
	// Whether that comes as a redirect or a re-rendered page is unverified, so
	// both are handled.
	page := resp
	if isRedirect(resp.status) {
		next, app, err := l.nextLocation(resp)
		if err != nil {
			return nil, err
		}
		if app != "" {
			return l.finishToken(ctx, app, c.verifier, c.state)
		}
		switch next.Path {
		case loginNewPath, loginPath:
			// Back at the start: the login session is gone.
			return nil, ErrMFAExpired
		case mfaPath, mfaPath + "/new":
			p, app, err := l.follow(ctx, next)
			if err != nil {
				c.keepSession(l)
				return nil, err
			}
			if app != "" {
				return l.finishToken(ctx, app, c.verifier, c.state)
			}
			page = p
		default:
			return l.finishToken(ctx, next.String(), c.verifier, c.state)
		}
	} else if app := l.appLink(resp); app != "" {
		return l.finishToken(ctx, app, c.verifier, c.state)
	}
	if page.status != http.StatusOK && page.status != http.StatusUnprocessableEntity {
		return nil, l.flowChanged("unrecognized response to two-factor code", page)
	}
	if info, err := parsePage(page.body); err != nil || info.form(mfaPath) == nil {
		return nil, l.flowChanged("unrecognized response to two-factor code", page)
	}
	// Wrong code: refresh the CSRF tokens and cookies from the challenge page
	// so the challenge can be re-marshaled and retried.
	if err := c.absorb(l, page, c.Method); err != nil {
		return nil, err
	}
	return nil, ErrInvalidMFACode
}
