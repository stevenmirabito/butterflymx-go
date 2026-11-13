package butterflymxtest

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The accounts app (rewritten by ButterflyMX in 2026) keeps its login session
// in identity_session and protects forms with a double-submit CSRF token: the
// _csrf_token cookie and the form's _csrf_token field must match.
const (
	sessionCookie = "identity_session"
	csrfCookie    = "_csrf_token"
	csrfField     = "_csrf_token"
)

// errInvalidLogin is the message the login page shows after a failed sign-in.
const errInvalidLogin = "Invalid email or password"

type session struct {
	id     string
	csrf   string     // the double-submit CSRF token (cookie and form field)
	params url.Values // the pending /oauth/authorize query
	pwOK   bool       // password accepted, 2FA pending
	authed bool       // fully authenticated
	mfa    mfaState

	// One-shot messages shown by the next render of the page they belong to.
	loginErr string // login page: error under the password field
	mfaFlash string // challenge page: notice or error at the top
	mfaErr   string // challenge page: error under the code field
}

type authCode struct {
	challenge, redirectURI, clientID, nonce string
	expires                                 time.Time
}

type accessToken struct {
	expires time.Time
}

type refreshToken struct {
	revoked bool
}

type apiToken struct {
	expires time.Time // zero: never
	revoked bool
}

func (s *Server) baseURL(r *http.Request) string { return "http://" + r.Host }

// session returns the session for the request's cookie, creating one when
// create is set and none exists. It (re)issues both cookies.
func (s *Server) session(w http.ResponseWriter, r *http.Request, create bool) *session {
	var sess *session
	if c, err := r.Cookie(sessionCookie); err == nil {
		sess = s.sessions[c.Value]
	}
	if sess == nil && create {
		sess = &session{id: randToken(48), csrf: randHex(32), mfa: newMFAState()}
		s.sessions[sess.id] = sess
	}
	if sess != nil {
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: sess.id, Path: "/", HttpOnly: true})
		http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: sess.csrf, Path: "/"})
	}
	return sess
}

// checkCSRF validates a form post: the form's _csrf_token must equal the
// session's token and the _csrf_token cookie. The app answers 403 when not.
func (sess *session) checkCSRF(r *http.Request) bool {
	if sess == nil {
		return false
	}
	c, err := r.Cookie(csrfCookie)
	f := r.PostFormValue(csrfField)
	return err == nil && f != "" && subtle.ConstantTimeCompare([]byte(f), []byte(sess.csrf)) == 1 &&
		subtle.ConstantTimeCompare([]byte(c.Value), []byte(sess.csrf)) == 1
}

func writeHTML(w http.ResponseWriter, status int, body string) {
	if status == http.StatusOK {
		w.Header().Set("ETag", weakETag([]byte(body)))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (s *Server) csrfFailure(w http.ResponseWriter) {
	writeHTML(w, http.StatusForbidden,
		"<!DOCTYPE html>\n<html><head><title>ButterflyMX - Forbidden</title></head>"+
			"<body><h1>Invalid CSRF token</h1></body></html>\n")
}

// page renders an accounts page in the layout of the captured ones: a
// flash area, a heading and the given inner HTML.
func (s *Server) page(title, flash, h1, h2, inner, footer string) string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html class=\"h-full\" lang=\"en\">\n <head>\n  <meta charset=\"utf-8\">\n  <title>ButterflyMX - " + html.EscapeString(title) + "</title>\n")
	b.WriteString("  <meta content=\"ButterflyMX\" name=\"description\">\n </head>\n <body class=\"h-full\">\n  <h2>Property access made simple</h2>\n  <main>\n   <div id=\"content\">\n    <div id=\"flash_messages\">")
	if flash != "" {
		b.WriteString("<div>" + html.EscapeString(flash) + "</div>")
	}
	b.WriteString("</div>\n    <h1>" + html.EscapeString(h1) + "</h1>\n")
	if h2 != "" {
		b.WriteString("    <h2>" + html.EscapeString(h2) + "</h2>\n")
	}
	b.WriteString(inner)
	b.WriteString(footer)
	b.WriteString("    <div>By signing in, you agree with our <a href=\"/terms-and-conditions\">Terms and Policies</a></div>\n")
	b.WriteString("    <div>©" + fmt.Sprint(s.now().Year()) + " ButterflyMX, Inc.</div>\n   </div>\n  </main>\n </body>\n</html>\n")
	return b.String()
}

func hidden(name, value string) string {
	return `<input type="hidden" name="` + name + `" value="` + html.EscapeString(value) + `" />`
}

func (s *Server) loginPage(sess *session, errMsg string) string {
	pwErr := ""
	if errMsg != "" {
		pwErr = `<ul class="text-red-1">` + html.EscapeString(errMsg) + `</ul>`
	}
	emailAttr := ` data-error="false"`
	if errMsg != "" {
		emailAttr = ` data-error="true"`
	}
	inner := `    <form autocomplete="off" novalidate action="/login" method="post">
     ` + hidden(csrfField, sess.csrf) + `
     ` + hidden("return_to", authorizeLocation(sess)) + `
     <div` + emailAttr + `>
      <label for="login_email"><span>Email</span></label>
      <input placeholder="Enter email here" autocomplete="email" type="email" name="email" id="login_email" value="" />
     </div>
     <div` + emailAttr + `>
      <label for="login_password"><span>Password</span></label>
      <input placeholder="Enter password here" autocomplete="current-password" type="password" name="password" id="login_password" />
      <button type="button" class="toggle-pw"><span class="sr-only">Toggle password reveal</span></button>
      ` + pwErr + `
     </div>
     <a href="/password/new">Forgot password?</a>
     <input type="submit" name="commit" value="Sign in with email" class="btn btn-primary" />
    </form>
    <div id="alternate-login-options">
     <form method="post" action="/sso/microsoft">
      ` + hidden(csrfField, sess.csrf) + `
      <button class="btn btn-vendored-signin" type="submit">Microsoft</button>
      ` + hidden("prompt", "select_account") + `
     </form>
     <form method="post" action="/sso/google">
      ` + hidden(csrfField, sess.csrf) + `
      <button class="btn btn-vendored-signin" type="submit">Google</button>
     </form>
    </div>
    <div>Don't know if you're registered? <a href="/registrations/new">Check here</a></div>
`
	return s.page("Sign in", "", "Sign in", "", inner, "")
}

func (s *Server) hLoginNew(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r, true)
	msg := sess.loginErr
	sess.loginErr = ""
	writeHTML(w, http.StatusOK, s.loginPage(sess, msg))
}

// authorizeLocation is the (relative) /oauth/authorize URL the sign-in
// returns to: the pending authorize query without prompt=login.
func authorizeLocation(sess *session) string {
	q := url.Values{}
	for k, v := range sess.params {
		if k != "prompt" {
			q[k] = v
		}
	}
	return "/oauth/authorize?" + q.Encode()
}

// redirect answers with a bare redirect like the accounts app's
// "Found. Redirecting to …" pages.
func redirect(w http.ResponseWriter, status int, location string) {
	w.Header().Set("Location", location)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "Redirecting to %s", location)
}

func (s *Server) hLogin(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r, false)
	if err := r.ParseForm(); err != nil || !sess.checkCSRF(r) {
		s.csrfFailure(w)
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	pw := r.PostFormValue("password")
	okEmail := subtle.ConstantTimeCompare([]byte(email), []byte(strings.ToLower(DefaultEmail))) == 1
	okPW := subtle.ConstantTimeCompare([]byte(pw), []byte(DefaultPassword)) == 1
	if !okEmail || !okPW {
		// The login page is shown again (after a redirect) with the error.
		sess.loginErr = errInvalidLogin
		redirect(w, http.StatusSeeOther, "/login/new")
		return
	}
	if s.cfg.mfa {
		sess.pwOK = true
		sess.authed = false
		sess.mfa = newMFAState()
		if s.cfg.mfaLand {
			redirect(w, http.StatusFound, mfaVerifyPath)
			return
		}
		redirect(w, http.StatusFound, mfaNewPath+"?type="+s.lastMFA)
		return
	}
	sess.pwOK, sess.authed = true, true
	redirect(w, http.StatusFound, authorizeLocation(sess))
}

func (s *Server) hAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	bad := func(desc string) {
		writeJSON(w, http.StatusBadRequest, "application/json; charset=utf-8",
			map[string]any{"error": "invalid_request", "error_description": desc})
	}
	switch {
	case q.Get("client_id") != ClientID:
		bad("Client authentication failed due to unknown client.")
		return
	case q.Get("redirect_uri") != RedirectURI:
		bad("The requested redirect uri is malformed or doesn't match client redirect URI.")
		return
	case q.Get("response_type") != "code":
		bad("The authorization server does not support this response type.")
		return
	case q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256":
		bad("PKCE with code_challenge_method=S256 is required.")
		return
	}
	sess := s.session(w, r, true)
	if sess.authed && q.Get("prompt") != "login" {
		code := randToken(32)
		s.codes[code] = &authCode{
			challenge: q.Get("code_challenge"), redirectURI: q.Get("redirect_uri"), clientID: q.Get("client_id"),
			nonce: q.Get("nonce"), expires: s.now().Add(10 * time.Minute),
		}
		out := url.Values{"code": {code}}
		if st := q.Get("state"); st != "" {
			out.Set("state", st)
		}
		// The app hand-off is a page with a link, not a redirect: the custom
		// URL scheme is opened by the browser (or the in-app web view).
		link := RedirectURI + "?" + out.Encode()
		writeHTML(w, http.StatusOK, `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Returning to app…</title></head>
<body><h1>Returning to app…</h1><p>Returning to the app… <a href="`+html.EscapeString(link)+`">Tap here if nothing happens</a></p></body></html>
`)
		return
	}
	sess.params = q
	sess.pwOK, sess.authed = false, false
	sess.mfa = newMFAState()
	redirect(w, http.StatusFound, "/login/new")
}

// ---- OAuth tokens ---------------------------------------------------------

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, "application/json; charset=utf-8", map[string]any{"error": code, "error_description": desc})
}

const invalidGrantDesc = "The provided authorization grant is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client."

func (s *Server) jwt(base string, claims map[string]any) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v, json.Deterministic(true))
		return base64.RawURLEncoding.EncodeToString(b)
	}
	claims["iss"] = base
	claims["sub"] = userID
	claims["jti"] = randHex(16)
	return enc(map[string]any{"alg": "RS256", "typ": "JWT", "kid": randHex(8)}) + "." + enc(claims) + "." + randToken(64)
}

func (s *Server) issueTokens(base, nonce string) map[string]any {
	now := s.now()
	exp := now.Add(s.cfg.tokenTTL)
	access := s.jwt(base, map[string]any{"aud": ClientID, "iat": now.Unix(), "exp": exp.Unix(), "scope": "openid profile"})
	refresh := randToken(32)
	s.accessTokens[access] = &accessToken{expires: exp}
	s.refreshTokens[refresh] = &refreshToken{}
	idClaims := map[string]any{"aud": ClientID, "iat": now.Unix(), "exp": exp.Unix(), "email": DefaultEmail}
	if nonce != "" {
		idClaims["nonce"] = nonce
	}
	return map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(s.cfg.tokenTTL.Seconds()),
		"refresh_token": refresh,
		"scope":         "openid profile",
		"created_at":    now.Unix(),
		"id_token":      s.jwt(base, idClaims),
	}
}

func (s *Server) hToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "Malformed form body.")
		return
	}
	if r.PostFormValue("client_id") != ClientID {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method.")
		return
	}
	switch g := r.PostFormValue("grant_type"); g {
	case "authorization_code":
		code := r.PostFormValue("code")
		ac := s.codes[code]
		delete(s.codes, code) // single use, even when the attempt fails
		if ac == nil || !s.now().Before(ac.expires) ||
			ac.clientID != r.PostFormValue("client_id") || ac.redirectURI != r.PostFormValue("redirect_uri") {
			oauthError(w, http.StatusBadRequest, "invalid_grant", invalidGrantDesc)
			return
		}
		sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(ac.challenge)) != 1 {
			oauthError(w, http.StatusBadRequest, "invalid_grant", invalidGrantDesc)
			return
		}
		writeJSON(w, http.StatusOK, "application/json; charset=utf-8", s.issueTokens(s.baseURL(r), ac.nonce))
	case "refresh_token":
		rt := r.PostFormValue("refresh_token")
		t := s.refreshTokens[rt]
		if t == nil || t.revoked {
			oauthError(w, http.StatusBadRequest, "invalid_grant", invalidGrantDesc)
			return
		}
		// Rotation: the old refresh token dies, a new pair is issued. The old
		// access token stays valid until it expires.
		delete(s.refreshTokens, rt)
		writeJSON(w, http.StatusOK, "application/json; charset=utf-8", s.issueTokens(s.baseURL(r), ""))
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "The authorization grant type is not supported by the authorization server.")
	}
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// oauthValid reports whether tok is a live OAuth access token.
func (s *Server) oauthValid(tok string) (ok bool, expired bool) {
	t := s.accessTokens[tok]
	if t == nil {
		return false, false
	}
	if !s.now().Before(t.expires) {
		return false, true
	}
	return true, false
}

func unauthorized(w http.ResponseWriter, desc string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="ButterflyMX", error="invalid_token"`)
	writeJSON(w, http.StatusUnauthorized, "application/json; charset=utf-8",
		map[string]any{"error": "invalid_token", "error_description": desc})
}

func (s *Server) hRegions(w http.ResponseWriter, r *http.Request) {
	if ok, expired := s.oauthValid(bearer(r)); !ok {
		if expired {
			unauthorized(w, "The access token expired")
		} else {
			unauthorized(w, "The access token is invalid")
		}
		return
	}
	writeCached(w, r, "application/json; charset=utf-8", map[string]any{"regions": []string{"na"}})
}
