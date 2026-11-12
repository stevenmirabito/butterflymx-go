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

const sessionCookie = "_accounts_session"

type session struct {
	id     string
	params url.Values // the pending /oauth/authorize query
	pwOK   bool       // password accepted, 2FA pending
	authed bool       // fully authenticated
	// csrf maps every issued authenticity token to the form it was issued
	// for (the form's action, or csrfMeta for the page's meta tag).
	csrf map[string]string
	mfa  mfaState
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
// create is set and none exists. It (re)issues the cookie like Rails does.
func (s *Server) session(w http.ResponseWriter, r *http.Request, create bool) *session {
	var sess *session
	if c, err := r.Cookie(sessionCookie); err == nil {
		sess = s.sessions[c.Value]
	}
	if sess == nil && create {
		sess = &session{id: randToken(48), csrf: map[string]string{}, mfa: newMFAState()}
		s.sessions[sess.id] = sess
	}
	if sess != nil {
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: sess.id, Path: "/", HttpOnly: true})
	}
	return sess
}

// csrfMeta is the purpose of the token in the page's csrf-token meta tag.
const csrfMeta = "meta"

// newCSRF issues a fresh authenticity token for the form with the given
// action (or csrfMeta). Every form gets its own token, as in the real app.
func (sess *session) newCSRF(purpose string) string {
	t := randToken(64)
	sess.csrf[t] = purpose
	return t
}

// formCSRF validates only the authenticity_token form field against the form
// that posts to action. Plain form posts (method picker, resend) carry no
// X-CSRF-Token header.
func (sess *session) formCSRF(r *http.Request, action string) bool {
	if sess == nil {
		return false
	}
	f := r.PostFormValue("authenticity_token")
	p, ok := sess.csrf[f]
	return f != "" && ok && p == action
}

// checkCSRF validates both the X-CSRF-Token header (the meta tag's token) and
// the authenticity_token of the form posting to action. The Rails app answers
// 422 when they are bad.
func (sess *session) checkCSRF(r *http.Request, action string) bool {
	if sess == nil {
		return false
	}
	h := r.Header.Get("X-CSRF-Token")
	p, ok := sess.csrf[h]
	return h != "" && ok && p == csrfMeta && sess.formCSRF(r, action)
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
	writeHTML(w, http.StatusUnprocessableEntity,
		"<!DOCTYPE html>\n<html><head><title>ButterflyMX - Invalid authenticity token</title></head>"+
			"<body><h1>Invalid authenticity token</h1></body></html>\n")
}

// page renders an accounts page like the fixtures: csrf-param and csrf-token
// meta tags, flash messages, a heading and the given inner HTML.
func page(title, metaToken, flash, h1, h2, inner string) string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n <head>\n  <title>\n   ButterflyMX - " + html.EscapeString(title) + "\n  </title>\n")
	b.WriteString("  <meta content=\"authenticity_token\" name=\"csrf-param\"/>\n")
	b.WriteString("  <meta content=\"" + html.EscapeString(metaToken) + "\" name=\"csrf-token\"/>\n </head>\n <body>\n  <div>\n   <h2>\n    Property access made simple\n   </h2>\n  </div>\n  <main>\n   <div id=\"content\">\n")
	b.WriteString("    <div id=\"flash_messages\">\n")
	if flash != "" {
		b.WriteString("     <div>\n      <div>\n       <div>\n        <div classs=\"text-sm font-semibold\">\n         " + html.EscapeString(flash) + "\n        </div>\n       </div>\n      </div>\n     </div>\n")
	}
	b.WriteString("    </div>\n    <div>\n     <a href=\"https://butterflymx.com\"></a>\n     <h1>\n      " + html.EscapeString(h1) + "\n     </h1>\n")
	if h2 != "" {
		b.WriteString("     <h2>\n      " + html.EscapeString(h2) + "\n     </h2>\n")
	}
	b.WriteString(inner)
	b.WriteString("     <div>\n      By signing in, you agree with our\n      <a href=\"/terms-and-conditions\" target=\"_top\">Terms and Policies</a>\n     </div>\n")
	b.WriteString("    </div>\n   </div>\n  </main>\n </body>\n</html>\n")
	return b.String()
}

func hidden(name, value string) string {
	return `<input name="` + name + `" type="hidden" value="` + html.EscapeString(value) + `"/>`
}

func (s *Server) loginPage(sess *session, flash string) string {
	meta := sess.newCSRF(csrfMeta)
	form := sess.newCSRF("/login")
	inner := `     <form accept-charset="UTF-8" action="/login" autocomplete="off" method="post" novalidate="novalidate">
      ` + hidden("authenticity_token", form) + `
      <label for="login_email"><span>Email</span></label>
      <input autocomplete="email" id="login_email" name="login[email]" placeholder="Enter email here" type="email"/>
      <label for="login_password"><span>Password</span></label>
      <input autocomplete="current-password" id="login_password" name="login[password]" placeholder="Enter password here" type="password"/>
      <a href="/password/new">Forgot password?</a>
      <a href="/registrations/new">Create an account</a>
      <input name="commit" type="submit" value="Sign in with email"/>
     </form>
     <div id="alternate-login-options">
      <form action="/sso/microsoft" method="post">
       <button type="submit">Microsoft</button>
       ` + hidden("authenticity_token", randToken(64)) + hidden("prompt", "select_account") + `
      </form>
      <form action="/sso/google" method="post">
       <button type="submit">Google</button>
       ` + hidden("authenticity_token", randToken(64)) + hidden("prompt", "select_account") + `
      </form>
     </div>
`
	return page("Sign in", meta, flash, "Sign in", "", inner)
}

func (s *Server) hLoginNew(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r, true)
	writeHTML(w, http.StatusOK, s.loginPage(sess, ""))
}

// authorizeLocation is the (relative) /oauth/authorize URL the turbo-stream
// redirects to: the pending authorize query without prompt=login.
func authorizeLocation(sess *session) string {
	q := url.Values{}
	for k, v := range sess.params {
		if k != "prompt" {
			q[k] = v
		}
	}
	return "/oauth/authorize?" + q.Encode()
}

func turboRedirect(w http.ResponseWriter, location string) {
	body := fmt.Sprintf(`<turbo-stream location="%s" action="redirect_to"><template></template></turbo-stream>`, html.EscapeString(location))
	w.Header().Set("ETag", weakETag([]byte(body)))
	w.Header().Set("Content-Type", "text/vnd.turbo-stream.html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

func (s *Server) hLogin(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r, false)
	if err := r.ParseForm(); err != nil || !sess.checkCSRF(r, "/login") {
		s.csrfFailure(w)
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("login[email]")))
	pw := r.PostFormValue("login[password]")
	okEmail := subtle.ConstantTimeCompare([]byte(email), []byte(strings.ToLower(DefaultEmail))) == 1
	okPW := subtle.ConstantTimeCompare([]byte(pw), []byte(DefaultPassword)) == 1
	if !okEmail || !okPW {
		// The real server's status is unverified; the fake renders the form again.
		writeHTML(w, http.StatusUnprocessableEntity, s.loginPage(sess, "Invalid email or password."))
		return
	}
	if s.cfg.mfa {
		sess.pwOK = true
		sess.authed = false
		sess.mfa = newMFAState()
		w.Header().Set("Location", s.baseURL(r)+"/sessions/two_factor_authentication/new?type="+s.lastMFA)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusSeeOther)
		return
	}
	sess.pwOK, sess.authed = true, true
	turboRedirect(w, authorizeLocation(sess))
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
		w.Header().Set("Location", RedirectURI+"?"+out.Encode())
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusFound)
		return
	}
	sess.params = q
	sess.pwOK, sess.authed = false, false
	sess.mfa = newMFAState()
	w.Header().Set("Location", s.baseURL(r)+"/login/new")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusFound)
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
