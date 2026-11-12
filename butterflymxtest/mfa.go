package butterflymxtest

import (
	"fmt"
	"html"
	"math/rand/v2"
	"net/http"
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
	mfaVerifyPath = "/sessions/two_factor_authentication"
	mfaNewPath    = "/sessions/two_factor_authentication/new"
)

func validMFAMethod(m string) bool {
	return m == mfaAuthenticator || m == mfaSMS || m == mfaEmail
}

// mfaChooseAction is the action of the picker and resend forms of a method
// (and the purpose their authenticity tokens are issued for).
func mfaChooseAction(method string) string { return mfaNewPath + "?type=" + method }

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

// WithMFASendOnGET controls whether loading the challenge page of an SMS or
// email method (GET /sessions/two_factor_authentication/new?type=sms|email),
// as the app does right after the login redirect, itself sends a code. With
// true (the default) the first such GET of a login session sends a code and
// later GETs do not send again. With false only choosing the method in the
// picker and the "Resend code" form send codes.
//
// The real server does send on that GET, which is why true is the
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

// mfaLayout renders a 2FA page with the layout of the captured pages.
func (s *Server) mfaLayout(title, meta, flash, h1, h2, content, footer string) string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n <head>\n  <title>\n   ButterflyMX - " + html.EscapeString(title) + "\n  </title>\n")
	b.WriteString("  <meta content=\"authenticity_token\" name=\"csrf-param\"/>\n")
	b.WriteString("  <meta content=\"" + html.EscapeString(meta) + "\" name=\"csrf-token\"/>\n </head>\n")
	b.WriteString(` <body>
  <div>
   <div>
    <div>
     <div>
      <div>
       <h2>
        Property access made simple
       </h2>
      </div>
     </div>
    </div>
   </div>
   <main>
    <div id="content">
     <div id="flash_messages">
`)
	if flash != "" {
		b.WriteString("      <div>\n       <div>\n        <div>\n         <div classs=\"text-sm font-semibold\">\n          " +
			html.EscapeString(flash) + "\n         </div>\n        </div>\n        <div>\n        </div>\n       </div>\n      </div>\n")
	}
	b.WriteString(`     </div>
     <div>
      <div>
       <div>
        <div>
         <a href="https://butterflymx.com">
         </a>
        </div>
       </div>
       <div>
        <div>
         <h1>
          ` + html.EscapeString(h1) + `
         </h1>
         <h2>
          ` + html.EscapeString(h2) + `
         </h2>
        </div>
        <div>
`)
	b.WriteString(content)
	b.WriteString(`        </div>
       </div>
       <div>
` + footer + `        <div>
         ©` + fmt.Sprint(s.now().Year()) + `  ButterflyMX, Inc.
        </div>
       </div>
      </div>
     </div>
    </div>
   </main>
  </div>
 </body>
</html>
`)
	return b.String()
}

const termsFooter = `        <div>
         <div>
          By signing in, you agree with our
          <a href="/terms-and-conditions" target="_top">
           Terms and Policies
          </a>
         </div>
        </div>
`

const supportFooter = `        <div>
         <div>
          If you can't verify your account, contact us:
         </div>
         <a href="mailto:support@butterflymx.com">
          support@butterflymx.com
         </a>
         <a href="tel:8003984416">
          (800) 398-4416
         </a>
        </div>
`

func hiddenInput(name, value string) string {
	return `<input name="` + name + `" type="hidden" value="` + html.EscapeString(value) + `"/>`
}

// twoFactorPage renders the challenge page of a method. Each form gets its
// own authenticity token. flash is the notice or error at the top, fieldErr
// the error under the code field.
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
	meta := sess.newCSRF(csrfMeta)
	errHTML := ""
	if fieldErr != "" {
		errHTML = "\n            <ul>\n             " + html.EscapeString(fieldErr) + "\n            </ul>"
	}
	content := `         <form accept-charset="UTF-8" action="` + mfaVerifyPath + `" method="post">
          ` + hiddenInput("authenticity_token", sess.newCSRF(mfaVerifyPath)) + `
          <input id="type" name="type" type="hidden" value="` + method + `"/>
          <div>
           <div>
            <label for="code">
             <span>
              Verification code
             </span>
            </label>
            <input autocomplete="one-time-code" id="code" inputmode="numeric" maxlength="6" name="code" pattern="[0-9]*" size="6" type="text"/>` + errHTML + `
           </div>
          </div>
          <input name="commit" type="submit" value="Use code"/>
         </form>
`
	if method != mfaAuthenticator {
		action := mfaChooseAction(method)
		content += `         <form action="` + action + `" method="post">
          <button type="submit">
           Resend code
          </button>
          ` + hiddenInput("authenticity_token", sess.newCSRF(action)) + `
          ` + hiddenInput("context", "resend") + `
         </form>
`
	}
	content += `         <a href="` + mfaVerifyPath + `">
          Verify another way
         </a>
`
	return s.mfaLayout(title, meta, flash, title, h2, content, termsFooter)
}

// twoFactorPicker renders the method picker: one one-button form per method.
func (s *Server) twoFactorPicker(sess *session) string {
	meta := sess.newCSRF(csrfMeta)
	var content strings.Builder
	for _, m := range []struct{ typ, img, name, desc string }{
		{mfaEmail, "email-28f4bfc7", "Email", "Receive a code from your ButterflyMX email address"},
		{mfaSMS, "text-0ca07fd0", "Text message", "Receive a code via text on your mobile device"},
		{mfaAuthenticator, "authenticator-237155f6", "Authenticator app", "Receive a code from an authenticator app"},
	} {
		action := mfaChooseAction(m.typ)
		content.WriteString(`         <form action="` + action + `" method="post">
          <button type="submit">
           <div>
            <img src="/assets/authentication/` + m.img + `.svg"/>
           </div>
           <div>
            <h3>
             ` + m.name + `
            </h3>
            <div>
             ` + m.desc + `
            </div>
           </div>
           <div>
           </div>
          </button>
          ` + hiddenInput("authenticity_token", sess.newCSRF(action)) + `
         </form>
`)
	}
	return s.mfaLayout("How do you want to verify your account?", meta, "",
		"How do you want to verify your account?",
		"Choose one of the following options to use a 2nd factor authentication method",
		content.String(), supportFooter)
}

func unknownMFAMethod(w http.ResponseWriter, status int) {
	writeHTML(w, status, "<!DOCTYPE html>\n<html><head><title>ButterflyMX - Not found</title></head>"+
		"<body><h1>Unknown verification method</h1></body></html>\n")
}

// ---- handlers --------------------------------------------------------------

func (s *Server) loginRedirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", s.baseURL(r)+"/login/new")
	w.WriteHeader(http.StatusFound)
}

func (s *Server) hTwoFactorNew(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r, false)
	if sess == nil || !sess.pwOK {
		s.loginRedirect(w, r)
		return
	}
	method := r.URL.Query().Get("type")
	if !validMFAMethod(method) {
		unknownMFAMethod(w, http.StatusNotFound)
		return
	}
	if s.cfg.mfaGET && method != mfaAuthenticator && !sess.mfa.sent[method] {
		s.sendMFA(sess, method, "challenge-get")
	}
	writeHTML(w, http.StatusOK, s.twoFactorPage(sess, method, "", ""))
}

func (s *Server) hTwoFactorPicker(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r, false)
	if sess == nil || !sess.pwOK {
		s.loginRedirect(w, r)
		return
	}
	writeHTML(w, http.StatusOK, s.twoFactorPicker(sess))
}

// hTwoFactorChoose handles the picker forms and the resend form. Both are
// plain form posts that carry only their own authenticity token.
func (s *Server) hTwoFactorChoose(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r, false)
	method := r.URL.Query().Get("type")
	if !validMFAMethod(method) {
		unknownMFAMethod(w, http.StatusNotFound)
		return
	}
	if err := r.ParseForm(); err != nil || sess == nil || !sess.pwOK || !sess.formCSRF(r, mfaChooseAction(method)) {
		s.csrfFailure(w)
		return
	}
	resend := r.PostFormValue("context") == "resend"
	notice := ""
	if method != mfaAuthenticator {
		trigger := "picker"
		if resend {
			trigger = "resend"
			notice = "A code has been sent to your phone number."
			if method == mfaEmail {
				notice = "A code has been sent to your email."
			}
		}
		s.sendMFA(sess, method, trigger)
	}
	writeHTML(w, http.StatusOK, s.twoFactorPage(sess, method, notice, ""))
}

func (s *Server) hTwoFactor(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r, false)
	if err := r.ParseForm(); err != nil || !sess.checkCSRF(r, mfaVerifyPath) || !sess.pwOK {
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
		writeHTML(w, http.StatusUnprocessableEntity, s.twoFactorPage(sess, method,
			"Two factor authentication failed.", "Invalid code, please try again or request a new code."))
		return
	}
	s.lastMFA = method
	sess.authed = true
	turboRedirect(w, authorizeLocation(sess))
}
