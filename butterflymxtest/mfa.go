package butterflymxtest

import (
	"fmt"
	"html"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Two-factor methods, as in the type= query parameter of the real app.
const (
	mfaAuthenticator = "authenticator_app"
	mfaSMS           = "sms"
	mfaEmail         = "email"
)

const (
	mfaCodeTTL    = 10 * time.Minute
	mfaMaskedSMS  = "******0100" // the fake resident's phone number +15555550100
	mfaVerifyPath = "/login/two_factor_authentication"
	mfaNewPath    = "/login/two_factor_authentication/new"
)

func validMFAMethod(m string) bool {
	return m == mfaAuthenticator || m == mfaSMS || m == mfaEmail
}

// mfaChooseAction is the action of the resend form of a method.
func mfaChooseAction(method string) string { return mfaNewPath + "?type=" + method }

// mfaPickerLink is the picker's link for a method.
func mfaPickerLink(method string) string {
	return mfaNewPath + "?type=" + method + "&account_id=" + url.QueryEscape(userID)
}

// WithLastMFAMethod sets the second-factor method the resident used last
// ("authenticator_app", "sms" or "email"). POST /login redirects to the
// challenge page of that method. The default is "authenticator_app". It
// panics on any other value.
func WithLastMFAMethod(method string) Option {
	if !validMFAMethod(method) {
		panic("butterflymxtest: WithLastMFAMethod: unknown method " + method)
	}
	return func(c *config) { c.lastMFA = method }
}

// WithMFAPickerLanding makes POST /login redirect to the method picker
// (GET /login/two_factor_authentication) instead of the challenge page of the
// last used method. The real server does this for some accounts: nothing is
// sent until a method is chosen.
func WithMFAPickerLanding() Option { return func(c *config) { c.mfaLand = true } }

// WithMFASendOnGET controls whether loading the challenge page of an SMS or
// email method (GET /login/two_factor_authentication/new?type=sms|email), as
// the app does right after the login redirect, itself sends a code. With
// true (the default) the first such GET of a login session sends a code and
// later GETs do not send again. With false only choosing the method in the
// picker (a GET with an account_id) and the "Resend code" form send codes.
//
// The old real server sent on that GET (the current one is assumed to), which is why true is the
// default. Whether a repeated GET of the same
// page sends again is unknown. False exists to test clients against a server
// that behaves differently.
func WithMFASendOnGET(send bool) Option { return func(c *config) { c.mfaGET = send } }

// MFADelivery records one SMS or email code the fake "sent".
type MFADelivery struct {
	// Method is "sms" or "email".
	Method string
	// Destination is the masked phone number "******0100" for sms and
	// "resident@example.com" for email.
	Destination string
	// Code is the 6-digit code (it may start with a zero).
	Code string
	// At is the server clock time of the send.
	At time.Time
	// Resend is true for a code sent by the "Resend code" form.
	Resend bool
	// Trigger is what sent the code: "picker" (the method was chosen on the
	// method picker), "resend" (the resend form) or "challenge-get" (the GET
	// of the challenge page, see [WithMFASendOnGET]).
	Trigger string
}

// MFADeliveries returns every code sent so far, oldest first.
func (s *Server) MFADeliveries() []MFADelivery {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]MFADelivery(nil), s.deliveries...)
}

// LastMFACode returns the most recently sent code of method ("sms" or
// "email"), or "" when none was sent.
func (s *Server) LastMFACode(method string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.deliveries) - 1; i >= 0; i-- {
		if s.deliveries[i].Method == method {
			return s.deliveries[i].Code
		}
	}
	return ""
}

type mfaCode struct {
	code    string
	expires time.Time
}

// mfaState is the 2FA state of one login attempt (session).
type mfaState struct {
	codes map[string][]mfaCode // every code sent per method; all stay valid
	sent  map[string]bool      // a code was sent for the method in this login
}

func newMFAState() mfaState {
	return mfaState{codes: map[string][]mfaCode{}, sent: map[string]bool{}}
}

// sendMFA "sends" a fresh code over method. Earlier codes stay valid.
func (s *Server) sendMFA(sess *session, method, trigger string) {
	var code string
	for {
		code = fmt.Sprintf("%06d", rand.IntN(1_000_000))
		dup := false
		for _, c := range sess.mfa.codes[method] {
			dup = dup || c.code == code
		}
		if !dup {
			break
		}
	}
	now := s.now()
	sess.mfa.codes[method] = append(sess.mfa.codes[method], mfaCode{code: code, expires: now.Add(mfaCodeTTL)})
	sess.mfa.sent[method] = true
	dest := mfaMaskedSMS
	if method == mfaEmail {
		dest = DefaultEmail
	}
	s.deliveries = append(s.deliveries, MFADelivery{
		Method: method, Destination: dest, Code: code, At: now, Resend: trigger == "resend", Trigger: trigger,
	})
}

// mfaCodeValid reports whether code is an unexpired code sent in this login
// session over method.
func (s *Server) mfaCodeValid(sess *session, method, code string) bool {
	for _, c := range sess.mfa.codes[method] {
		if c.code == code && s.now().Before(c.expires) {
			return true
		}
	}
	return false
}

// ---- pages -----------------------------------------------------------------

const supportFooter = `    <div>If you can't verify your account, contact us:
     <a href="mailto:support@butterflymx.com">support@butterflymx.com</a>
     <a href="tel:8003984416">(800) 398-4416</a>
    </div>
`

func hiddenInput(name, value string) string { return hidden(name, value) }

// twoFactorPage renders the challenge page of a method. flash is the notice or
// error at the top, fieldErr the error under the code field.
func (s *Server) twoFactorPage(sess *session, method, flash, fieldErr string) string {
	var title, h2 string
	switch method {
	case mfaSMS:
		title, h2 = "Verify with text message", "A 6-digit code has been sent to your phone number "+mfaMaskedSMS
	case mfaEmail:
		title, h2 = "Verify with an Email", "A 6-digit code has been sent to your email"
	default:
		title, h2 = "Verify with an authenticator app", "Enter the verification code the authenticator app provides"
	}
	errHTML := ""
	if fieldErr != "" {
		errHTML = `<ul class="text-red-1">` + html.EscapeString(fieldErr) + `</ul>`
	}
	content := `    <form action="` + mfaVerifyPath + `" method="post">
     ` + hiddenInput(csrfField, sess.csrf) + `
     ` + hiddenInput("type", method) + `
     <label for="code"><span>Verification code</span></label>
     <input autocomplete="one-time-code" type="text" name="code" id="code" inputmode="numeric" maxlength="6" />
     ` + errHTML + `
     <input type="submit" value="Use code" class="btn btn-primary" />
    </form>
`
	if method != mfaAuthenticator {
		content += `    <form method="post" action="` + mfaChooseAction(method) + `">
     ` + hiddenInput(csrfField, sess.csrf) + `
     ` + hiddenInput("context", "resend") + `
     <button type="submit">Resend code</button>
    </form>
`
	}
	content += `    <a href="` + mfaVerifyPath + `">Verify another way</a>
`
	return s.page(title, flash, title, h2, content, "")
}

// twoFactorPicker renders the method picker: one link per method.
func (s *Server) twoFactorPicker() string {
	var content strings.Builder
	for _, m := range []struct{ typ, name, desc string }{
		{mfaEmail, "Email", "Receive a code from your ButterflyMX email address"},
		{mfaSMS, "Text message", "Receive a code via text on your mobile device"},
		{mfaAuthenticator, "Authenticator app", "Receive a code from an authenticator app"},
	} {
		content.WriteString(`    <a href="` + html.EscapeString(mfaPickerLink(m.typ)) + `">
     <h3>` + m.name + `</h3>
     <div>` + m.desc + `</div>
    </a>
`)
	}
	return s.page("How do you want to verify your account?", "",
		"How do you want to verify your account?",
		"Choose one of the following options to use a 2nd factor authentication method",
		content.String(), supportFooter)
}

func unknownMFAMethod(w http.ResponseWriter, status int) {
	writeHTML(w, status, "<!DOCTYPE html>\n<html><head><title>ButterflyMX - Not found</title></head>"+
		"<body><h1>Unknown verification method</h1></body></html>\n")
}

// ---- handlers --------------------------------------------------------------

func (s *Server) loginRedirect(w http.ResponseWriter) { redirect(w, http.StatusFound, "/login/new") }

func (s *Server) hTwoFactorNew(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r, false)
	if sess == nil || !sess.pwOK {
		s.loginRedirect(w)
		return
	}
	method := r.URL.Query().Get("type")
	if !validMFAMethod(method) {
		unknownMFAMethod(w, http.StatusNotFound)
		return
	}
	if method != mfaAuthenticator {
		switch {
		case r.URL.Query().Get("account_id") != "":
			// Following a picker link chooses the method and sends the code.
			s.sendMFA(sess, method, "picker")
		case s.cfg.mfaGET && !sess.mfa.sent[method]:
			s.sendMFA(sess, method, "challenge-get")
		}
	}
	flash, fieldErr := sess.mfaFlash, sess.mfaErr
	sess.mfaFlash, sess.mfaErr = "", ""
	writeHTML(w, http.StatusOK, s.twoFactorPage(sess, method, flash, fieldErr))
}

func (s *Server) hTwoFactorPicker(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r, false)
	if sess == nil || !sess.pwOK {
		s.loginRedirect(w)
		return
	}
	writeHTML(w, http.StatusOK, s.twoFactorPicker())
}

// hTwoFactorResend handles the "Resend code" form and redirects back to the
// challenge page.
func (s *Server) hTwoFactorResend(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r, false)
	method := r.URL.Query().Get("type")
	if !validMFAMethod(method) {
		unknownMFAMethod(w, http.StatusNotFound)
		return
	}
	if err := r.ParseForm(); err != nil || sess == nil || !sess.pwOK || !sess.checkCSRF(r) {
		s.csrfFailure(w)
		return
	}
	if method != mfaAuthenticator && r.PostFormValue("context") == "resend" {
		s.sendMFA(sess, method, "resend")
		sess.mfaFlash = "A code has been sent to your phone number."
		if method == mfaEmail {
			sess.mfaFlash = "A code has been sent to your email."
		}
	}
	redirect(w, http.StatusFound, mfaNewPath+"?type="+method)
}

func (s *Server) hTwoFactor(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r, false)
	if err := r.ParseForm(); err != nil || !sess.checkCSRF(r) || !sess.pwOK {
		s.csrfFailure(w)
		return
	}
	method := r.PostFormValue("type")
	if !validMFAMethod(method) {
		unknownMFAMethod(w, http.StatusUnprocessableEntity)
		return
	}
	code := strings.ReplaceAll(strings.TrimSpace(r.PostFormValue("code")), " ", "")
	var ok bool
	if method == mfaAuthenticator {
		ok = totpValid(s.totpSecret, code, s.now())
	} else {
		ok = s.mfaCodeValid(sess, method, code)
	}
	if !ok {
		// A wrong code answers 200 with the challenge page re-rendered (and the
		// same CSRF token), an error under the code field.
		writeHTML(w, http.StatusOK, s.twoFactorPage(sess, method, "", "Invalid verification code"))
		return
	}
	s.lastMFA = method
	sess.authed = true
	redirect(w, http.StatusFound, authorizeLocation(sess))
}
