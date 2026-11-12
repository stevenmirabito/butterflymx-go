package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	maxHops     = 10
	mfaPath     = "/sessions/two_factor_authentication"
	loginPath   = "/login"
	turboAccept = "text/vnd.turbo-stream.html, text/html, application/xhtml+xml"
	htmlAccept  = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
)

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

func (l *loginClient) send(ctx context.Context, method string, u *url.URL, form url.Values, csrf string) (*response, error) {
	return l.do(ctx, method, u, form, csrf, false)
}

// sendPlainForm posts a form the way the browser does for a plain
// <form method="post">: browser-style Accept, no X-CSRF-Token header (the
// token travels only in the body).
func (l *loginClient) sendPlainForm(ctx context.Context, u *url.URL, form url.Values) (*response, error) {
	return l.do(ctx, http.MethodPost, u, form, "", true)
}

func (l *loginClient) do(ctx context.Context, method string, u *url.URL, form url.Values, csrf string, plain bool) (*response, error) {
	if u.Host != l.base.Host {
		return nil, fmt.Errorf("%w: unexpected host %q", ErrLoginFlowChanged, u.Host)
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", l.cfg.WebUserAgent)
	switch {
	case method == http.MethodPost && plain:
		req.Header.Set("Accept", htmlAccept)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", l.base.Scheme+"://"+l.base.Host)
	case method == http.MethodPost:
		req.Header.Set("Accept", turboAccept)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Origin", l.base.Scheme+"://"+l.base.Host)
	default:
		req.Header.Set("Accept", htmlAccept)
	}
	resp, err := l.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	return &response{status: resp.StatusCode, header: resp.Header, body: string(b), url: u}, nil
}

func isRedirect(status int) bool { return status >= 300 && status < 400 }

// follow performs a GET and manually follows redirects (max maxHops) until a
// non-redirect page, or a Location starting with the app redirect URI, whose
// raw value is returned as appRedirect.
func (l *loginClient) follow(ctx context.Context, u *url.URL) (page *response, appRedirect string, err error) {
	for range maxHops {
		r, err := l.send(ctx, http.MethodGet, u, nil, "")
		if err != nil {
			return nil, "", err
		}
		if !isRedirect(r.status) {
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

// nextLocation resolves a redirect's Location. app is non-empty when it
// points at the app redirect URI.
func (l *loginClient) nextLocation(r *response) (next *url.URL, app string, err error) {
	loc := r.header.Get("Location")
	if loc == "" {
		return nil, "", fmt.Errorf("%w: redirect without Location", ErrLoginFlowChanged)
	}
	if strings.HasPrefix(loc, l.cfg.RedirectURI) {
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
	csrfMeta string
	forms    []formInfo
	turboLoc string // location attribute of a <turbo-stream>
	hasTurbo bool
	text     string // visible text, whitespace-normalized
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func parsePage(body string) (*pageInfo, error) {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	p := &pageInfo{}
	var text strings.Builder
	var cur *formInfo
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode && n.Parent != nil && n.Parent.Data != "script" && n.Parent.Data != "style" {
			text.WriteString(n.Data)
			text.WriteByte(' ')
		}
		if n.Type == html.ElementNode {
			switch n.Data {
			case "meta":
				if attr(n, "name") == "csrf-token" && p.csrfMeta == "" {
					p.csrfMeta = attr(n, "content")
				}
			case "turbo-stream":
				if loc := attr(n, "location"); loc != "" && !p.hasTurbo {
					p.hasTurbo, p.turboLoc = true, loc
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

func (l *loginClient) flowChanged(what string, r *response) error {
	body := r.body
	for _, s := range l.secrets {
		if s != "" {
			body = strings.ReplaceAll(body, s, "[redacted]")
		}
	}
	// CSRF tokens and similar long opaque values must not end up in errors.
	body = opaqueRun.ReplaceAllString(body, "[redacted]")
	return fmt.Errorf("%w: %s (HTTP %d): %s", ErrLoginFlowChanged, what, r.status, truncate(strings.Join(strings.Fields(body), " "), 300))
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
// server texts or emails on loading that page). Choosing sms or email
// in the picker sends the code for m.
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
// one requested with [WithMFAMethod]. Use [SwitchMFAMethod] and
// [ResendMFACode] to change method or request another code.
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
	if form == nil || info.csrfMeta == "" || form.inputs["authenticity_token"] == "" {
		return nil, l.flowChanged("login form not found", page)
	}
	target, err := page.url.Parse(form.action)
	if err != nil {
		return nil, l.flowChanged("bad login form action", page)
	}
	resp, err := l.send(ctx, http.MethodPost, target, url.Values{
		"authenticity_token": {form.inputs["authenticity_token"]},
		"login[email]":       {email},
		"login[password]":    {password},
		"commit":             {"Sign in with email"},
	}, info.csrfMeta)
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
		case next.Path == "/oauth/authorize":
			return l.finish(ctx, next.String(), verifier, state)
		}
		return nil, l.flowChanged("unexpected redirect "+next.Path, resp)
	}
	rinfo, err := parsePage(resp.body)
	if err == nil {
		if rinfo.hasTurbo {
			loc, err := resp.url.Parse(rinfo.turboLoc)
			if err != nil {
				return nil, l.flowChanged("bad turbo-stream location", resp)
			}
			if strings.HasPrefix(rinfo.turboLoc, cfg.RedirectURI) {
				return l.finish(ctx, rinfo.turboLoc, verifier, state)
			}
			return l.finish(ctx, loc.String(), verifier, state)
		}
		if f := rinfo.form(loginPath); f != nil {
			if _, ok := f.inputs["login[email]"]; ok {
				return nil, ErrInvalidCredentials
			}
		}
	}
	return nil, l.flowChanged("unrecognized response to login", resp)
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
	if strings.HasPrefix(location, l.cfg.RedirectURI) {
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
	return completeFromCode(ctx, l.cfg, code, verifier)
}

// CompleteLogin submits the two-factor code and finishes the login. The
// verify form's type comes from the challenge page, so it works for every
// method. A wrong code returns [ErrInvalidMFACode] and updates c in place (the
// fresh verify, meta and resend CSRF tokens, and cookies) so it can be
// re-marshaled and retried. Challenges older than
// [MFAChallengeTTL] return [ErrMFAExpired].
func CompleteLogin(ctx context.Context, cfg Config, c *MFAChallenge, code string) (*Token, error) {
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
	target, err := l.base.Parse(c.action)
	if err != nil {
		return nil, ErrLoginFlowChanged
	}
	resp, err := l.send(ctx, http.MethodPost, target, url.Values{
		"authenticity_token": {c.csrfForm},
		"type":               {c.mfaType},
		"code":               {code},
		"commit":             {"Use code"},
	}, c.csrfMeta)
	if err != nil {
		return nil, err
	}
	if resp.status == http.StatusUnprocessableEntity {
		// Wrong code: refresh CSRF tokens and cookies from the re-rendered page.
		if err := c.absorb(l, resp, c.Method); err != nil {
			return nil, err
		}
		return nil, ErrInvalidMFACode
	}
	var location string
	if isRedirect(resp.status) {
		next, app, err := l.nextLocation(resp)
		if err != nil {
			return nil, err
		}
		location = app
		if app == "" {
			location = next.String()
		}
	} else if resp.status == http.StatusOK {
		info, err := parsePage(resp.body)
		if err != nil || !info.hasTurbo {
			return nil, l.flowChanged("unrecognized response to two-factor code", resp)
		}
		location = info.turboLoc
	} else {
		return nil, l.flowChanged("unrecognized response to two-factor code", resp)
	}
	return l.finishToken(ctx, location, c.verifier, c.state)
}
