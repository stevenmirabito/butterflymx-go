package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/stevenmirabito/butterflymx-go/auth"
)

const maxCodeAttempts = 3

// readLine reads one line from stdin, showing prompt on stderr. When stdin is
// a terminal and secret is set, the input is not echoed.
func (a *app) readLine(prompt string, secret bool) (string, error) {
	_, _ = fmt.Fprint(a.stderr, prompt)
	if f, ok := a.stdin.(*os.File); ok && secret && term.IsTerminal(int(f.Fd())) {
		b, err := term.ReadPassword(int(f.Fd()))
		_, _ = fmt.Fprintln(a.stderr)
		return strings.TrimSpace(string(b)), err
	}
	line, err := a.in.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		return "", fmt.Errorf("reading %s: %w", strings.TrimSpace(strings.TrimSuffix(prompt, ":")), err)
	}
	return strings.TrimSpace(line), nil
}

func (a *app) cmdLogin(args []string) error {
	fs := a.flagset("login")
	email := fs.String("email", "", "account email (default $BMX_EMAIL, else prompt)")
	code := fs.String("code", "", "two-factor code (default $BMX_TOTP_CODE, else prompt); SMS/email login sends a code automatically")
	mfaMethod := fs.String("mfa-method", "", "second factor to use: app, sms or email (default: the method of your last login)")
	pwStdin := fs.Bool("password-stdin", false, "read the password from the first line of stdin")
	browser := fs.Bool("browser", false, "sign in with a browser and paste back the redirect URL")
	if _, err := a.parse("login", fs, args, 0, 0); err != nil {
		return err
	}
	var opts []auth.LoginOption
	if *mfaMethod != "" {
		if *browser {
			return usagef("login: --mfa-method does not apply to --browser")
		}
		m, err := auth.ParseMFAMethod(*mfaMethod)
		if err != nil {
			return usagef("login: invalid --mfa-method %q (want app, sms or email)", *mfaMethod)
		}
		opts = append(opts, auth.WithMFAMethod(m))
	}

	var tok *auth.Token
	var err error
	if *browser {
		tok, err = a.loginBrowser()
	} else {
		tok, err = a.loginPassword(*email, *code, *pwStdin, opts)
	}
	if err != nil {
		return err
	}
	if err := a.saveToken(tok); err != nil {
		return fmt.Errorf("saving token: %w", err)
	}
	name := ""
	if c, err := a.client(); err == nil {
		if u, err := c.CurrentUser(a.ctx); err == nil {
			name = u.Email
		} else {
			_, _ = fmt.Fprintf(a.stderr, "bmx: warning: token saved but verifying it failed: %s\n", describeErr(err))
		}
	}
	if a.json {
		return a.emitJSON(map[string]any{"logged_in": true, "email": name, "token_file": a.tokenFile})
	}
	if name != "" {
		_, _ = fmt.Fprintf(a.stdout, "Logged in as %s. Token saved to %s\n", name, a.tokenFile)
	} else {
		_, _ = fmt.Fprintf(a.stdout, "Logged in. Token saved to %s\n", a.tokenFile)
	}
	return nil
}

func (a *app) loginPassword(email, code string, pwStdin bool, opts []auth.LoginOption) (*auth.Token, error) {
	if email == "" {
		email = a.getenv("BMX_EMAIL")
	}
	if email == "" {
		var err error
		if email, err = a.readLine("Email: ", false); err != nil {
			return nil, err
		}
	}
	password := a.getenv("BMX_PASSWORD")
	switch {
	case password != "":
	case pwStdin:
		line, err := a.in.ReadString('\n')
		if err != nil && (err != io.EOF || line == "") {
			return nil, fmt.Errorf("reading password from stdin: %w", err)
		}
		password = strings.TrimRight(line, "\r\n")
	default:
		var err error
		if password, err = a.readLine("Password: ", true); err != nil {
			return nil, err
		}
	}
	if email == "" || password == "" {
		return nil, usagef("login: email and password are required (BMX_PASSWORD, --password-stdin or a terminal prompt)")
	}

	res, err := auth.StartLogin(a.ctx, a.acfg, email, password, opts...)
	if err != nil {
		return nil, err
	}
	if res.Token != nil {
		return res.Token, nil
	}
	return a.completeChallenge(res.Challenge, code)
}

// completeChallenge asks for the second-factor code and finishes the login.
// A code given up front (--code, BMX_TOTP_CODE) is used as is, without a
// prompt. At the prompt the resident can also type "resend" or a method name
// ("sms", "email", "app") to get a code another way; those do not count as
// attempts. Wrong codes are retried up to maxCodeAttempts times in total.
func (a *app) completeChallenge(ch *auth.MFAChallenge, code string) (*auth.Token, error) {
	if code == "" {
		code = a.getenv("BMX_TOTP_CODE")
	}
	for attempt := 1; ; {
		if code == "" {
			in, err := a.readLine(mfaPrompt(ch), false)
			if err != nil {
				return nil, err
			}
			switch cmd := strings.ToLower(in); cmd {
			case "":
				continue
			case "resend":
				if !ch.CanResend() {
					_, _ = fmt.Fprintln(a.stderr, "The authenticator app has no code to resend.")
					continue
				}
				if err := auth.ResendMFACode(a.ctx, a.acfg, ch); err != nil {
					return nil, err
				}
				_, _ = fmt.Fprintf(a.stderr, "Code sent %s.\n", mfaWhere(ch))
				continue
			default:
				if m, err := auth.ParseMFAMethod(cmd); err == nil {
					if err := auth.SwitchMFAMethod(a.ctx, a.acfg, ch, m); err != nil {
						return nil, err
					}
					if ch.Method == auth.MFAAuthenticatorApp {
						_, _ = fmt.Fprintln(a.stderr, "Switched to the authenticator app.")
					} else {
						_, _ = fmt.Fprintf(a.stderr, "Code sent %s.\n", mfaWhere(ch))
					}
					continue
				}
			}
			code = in
		}
		tok, err := auth.CompleteLogin(a.ctx, a.acfg, ch, code)
		if err == nil {
			return tok, nil
		}
		if !errors.Is(err, auth.ErrInvalidMFACode) || attempt >= maxCodeAttempts {
			return nil, err
		}
		_, _ = fmt.Fprintf(a.stderr, "Invalid code (attempt %d of %d).\n", attempt, maxCodeAttempts)
		attempt++
		code = ""
	}
}

// mfaWhere says where the challenge's code was sent, e.g. "by text to
// ******0100" or "by email".
func mfaWhere(ch *auth.MFAChallenge) string {
	var s string
	switch ch.Method {
	case auth.MFASMS:
		s = "by text"
	case auth.MFAEmail:
		s = "by email"
	default:
		return "to your authenticator app"
	}
	if ch.Destination != "" {
		s += " to " + ch.Destination
	}
	return s
}

// mfaPrompt names the method, its destination and the other ways to get a code.
func mfaPrompt(ch *auth.MFAChallenge) string {
	if ch.Method == auth.MFAAuthenticatorApp {
		return "Enter the code from your authenticator app (or: sms / email): "
	}
	others := []string{"resend"}
	for _, o := range []struct {
		m    auth.MFAMethod
		name string
	}{{auth.MFASMS, "sms"}, {auth.MFAEmail, "email"}, {auth.MFAAuthenticatorApp, "app"}} {
		if o.m != ch.Method {
			others = append(others, o.name)
		}
	}
	return fmt.Sprintf("Enter the 6-digit code sent %s (or: %s): ", mfaWhere(ch), strings.Join(others, " / "))
}

func (a *app) loginBrowser() (*auth.Token, error) {
	flow := auth.NewAuthCodeFlow(a.acfg)
	start, err := flow.Start()
	if err != nil {
		return nil, err
	}
	_, _ = fmt.Fprintf(a.stderr, "Open this URL in a browser and sign in:\n\n%s\n\n", start.URL)
	_, _ = fmt.Fprintln(a.stderr, "The browser will end on a com.butterflymx.oauth://... address that it cannot open.")
	_, _ = fmt.Fprintln(a.stderr, "Copy that full address from the browser's developer tools or address bar.")
	redirected, err := a.readLine("Paste the redirect URL: ", false)
	if err != nil {
		return nil, err
	}
	return flow.Finish(a.ctx, start, redirected)
}

// saveToken replaces whatever token file exists.
func (a *app) saveToken(tok *auth.Token) error {
	prev, err := a.store.Load(a.ctx)
	if err != nil {
		// A corrupt file must not block a fresh login.
		if rerr := os.Remove(a.tokenFile); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			return err
		}
		prev = nil
	}
	return a.store.CompareAndSwap(a.ctx, prev, tok)
}

func (a *app) cmdLogout(args []string) error {
	fs := a.flagset("logout")
	if _, err := a.parse("logout", fs, args, 0, 0); err != nil {
		return err
	}
	tok, err := a.store.Load(a.ctx)
	if err != nil {
		// A corrupt file: just remove it.
		if derr := a.store.Delete(a.ctx); derr != nil {
			return derr
		}
		tok = nil
	}
	if tok != nil {
		env, err := a.environmentFor(tok)
		if err != nil {
			env = a.benv // still sign out locally
		}
		if err := a.authenticator(env).Logout(a.ctx); err != nil {
			if t, lerr := a.store.Load(a.ctx); lerr == nil && t == nil {
				return fmt.Errorf("local token removed, but server-side logout failed: %w", err)
			}
			return err
		}
	}
	if a.json {
		return a.emitJSON(map[string]any{"logged_out": tok != nil})
	}
	if tok == nil {
		_, _ = fmt.Fprintln(a.stdout, "Not logged in; nothing to do.")
	} else {
		_, _ = fmt.Fprintln(a.stdout, "Logged out.")
	}
	return nil
}

func (a *app) cmdWhoami(args []string) error {
	fs := a.flagset("whoami")
	if _, err := a.parse("whoami", fs, args, 0, 0); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	u, err := c.CurrentUser(a.ctx)
	if err != nil {
		return err
	}
	tenants, err := c.Tenants(a.ctx)
	if err != nil {
		return err
	}
	if a.json {
		return a.emitJSON(map[string]any{"user": u, "tenants": len(tenants)})
	}
	_, _ = fmt.Fprintf(a.stdout, "Name:      %s %s\n", u.FirstName, u.LastName)
	_, _ = fmt.Fprintf(a.stdout, "Email:     %s\n", u.Email)
	_, _ = fmt.Fprintf(a.stdout, "User ID:   %s\n", u.ID)
	_, _ = fmt.Fprintf(a.stdout, "2FA:       enabled=%v types=%s\n", u.TwoFactor.Enabled, strings.Join(u.TwoFactor.Types, ","))
	_, _ = fmt.Fprintf(a.stdout, "Tenants:   %d\n", len(tenants))
	return nil
}
