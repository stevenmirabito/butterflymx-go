package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Every error exit of the headless login must be free of what the user
// submitted and of text the server could have made up.

func TestServerSuppliedMethodNameIsNotEchoed(t *testing.T) {
	l := &loginClient{secrets: []string{"hunter2_secret", "123456"}}
	for in, want := range map[string]string{
		"carrier_pigeon":        "carrier_pigeon",
		"hunter2_secret":        "[redacted]", // a name that is a submitted secret
		"hunter2-secret":        "(unrecognized)",
		"has space":             "(unrecognized)",
		"":                      "(unrecognized)",
		strings.Repeat("a", 33): "(unrecognized)",
	} {
		if got := l.name(in); got != want {
			t.Errorf("name(%q) = %q, want %q", in, got, want)
		}
	}
	// End to end: a login redirect whose type is the submitted password.
	f := newFake(t)
	f.defaultMFA = testPassword
	_, err := StartLogin(context.Background(), f.cfg(), testEmail, testPassword)
	if !errors.Is(err, ErrMFAMethodUnsupported) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), testPassword) {
		t.Errorf("error echoes the password: %v", err)
	}
}

func TestAuthorizationErrorIsNotEchoed(t *testing.T) {
	cfg := Production
	_, err := codeFromRedirect(cfg, "com.butterflymx.oauth://oauth?error=123456&state=s", "s")
	if err == nil || strings.Contains(err.Error(), "123456") {
		t.Errorf("err = %v", err)
	}
	_, err = codeFromRedirect(cfg, "com.butterflymx.oauth://oauth?error=access_denied&state=s", "s")
	if err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Errorf("a standard error code should be kept: %v", err)
	}
}

func TestStructuredErrorsDropOpaqueValues(t *testing.T) {
	tok := strings.Repeat("A1b2", 12)
	if got := scrub("bad token " + tok + " rejected"); strings.Contains(got, tok) {
		t.Errorf("scrub kept the token: %q", got)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"error":"invalid_grant","error_description":"code %s is bad"}`, tok)
	}))
	defer srv.Close()
	cfg := Production.withDefaults()
	cfg.AccountsURL, cfg.APIURL = srv.URL, srv.URL
	_, _, err := postToken(context.Background(), cfg, "token", url.Values{"grant_type": {"authorization_code"}})
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != "invalid_grant" {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), tok) || strings.Contains(ae.Body, tok) || strings.Contains(ae.Description, tok) {
		t.Errorf("the error keeps the token: %+v", ae)
	}
}

// A transport failure for a URL the server chose must not carry its query.
func TestTransportErrorHidesTheQuery(t *testing.T) {
	cfg := Production.withDefaults()
	cfg.AccountsURL = "http://127.0.0.1:1" // nothing listens: connection refused
	l, err := newLoginClient(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	l.secrets = []string{"hunter2"}
	u, _ := url.Parse("http://127.0.0.1:1/next?password=hunter2&x=1")
	_, err = l.send(context.Background(), http.MethodGet, u, nil)
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "password=") {
		t.Errorf("error carries the query: %v", err)
	}
	var ne net.Error
	if !errors.As(err, &ne) {
		t.Errorf("the net.Error cause was lost: %v", err)
	}
}

func TestAppLinkAcceptsEscapedCustomRedirect(t *testing.T) {
	cfg := Production.withDefaults()
	cfg.RedirectURI = "myapp://oauth?tenant=1&mode=app"
	l := &loginClient{cfg: cfg}
	page := &response{status: 200, body: `<html><body><a href="myapp://oauth?tenant=1&amp;mode=app&amp;code=c&amp;state=s">Tap here</a></body></html>`}
	want := "myapp://oauth?tenant=1&mode=app&code=c&state=s"
	if got := l.appLink(page); got != want {
		t.Errorf("appLink = %q, want %q", got, want)
	}
}

func TestOpaqueRedirectsAreCompared(t *testing.T) {
	cfg := Production
	cfg.RedirectURI = "myapp:callback"
	if !cfg.isAppRedirect("myapp:callback?code=c") {
		t.Error("the configured opaque redirect was refused")
	}
	if cfg.isAppRedirect("myapp:other?code=c&state=s") {
		t.Error("a different opaque target was accepted")
	}
}

// net/http's own error text can quote what the server sent, such as a
// malformed status line: that part must be redacted too, with the cause kept.
func TestTransportCauseIsRedacted(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 4096)
			_, _ = c.Read(buf)
			_, _ = c.Write([]byte("HTTP/1.1 hunter2 denied\r\n\r\n"))
			_ = c.Close()
		}
	}()
	cfg := Production.withDefaults()
	cfg.AccountsURL = "http://" + ln.Addr().String()
	l, err := newLoginClient(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	l.secrets = []string{"hunter2"}
	u, _ := url.Parse(cfg.AccountsURL + "/next")
	_, err = l.send(context.Background(), http.MethodGet, u, nil)
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error quotes the secret: %v", err)
	}
	if errors.Unwrap(err) == nil {
		t.Error("the original cause was dropped")
	}
}

// Truncating before scrubbing could cut a token below the length scrub
// recognizes; and known secrets are removed, not only long runs.
func TestScrubbingOrderAndSecrets(t *testing.T) {
	tok := strings.Repeat("A1b2", 12) // 48 characters
	body := strings.Repeat(" ", 180) + tok
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprint(w, body)
	}))
	defer srv.Close()
	cfg := Production.withDefaults()
	cfg.AccountsURL, cfg.APIURL = srv.URL, srv.URL

	_, err := Regions(context.Background(), cfg, tok)
	var ae *Error
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(ae.Body, tok[:10]) {
		t.Errorf("a token prefix survived truncation: %q", ae.Body)
	}

	// A token endpoint that echoes what was submitted, with a code it made up.
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"error":"made-up-123456","error_description":"code 123456 and verifier abc123"}`)
	}))
	defer echo.Close()
	cfg.AccountsURL = echo.URL
	_, _, err = postToken(context.Background(), cfg, "token", url.Values{"code": {"123456"}, "code_verifier": {"abc123"}})
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v", err)
	}
	for _, leak := range []string{"123456", "abc123"} {
		if strings.Contains(ae.Description, leak) || strings.Contains(ae.Body, leak) || strings.Contains(ae.Code, leak) {
			t.Errorf("error keeps %q: %+v", leak, ae)
		}
	}
	if ae.Code != "unrecognized" {
		t.Errorf("Code = %q, want the made-up code not echoed", ae.Code)
	}
	// A standard code survives (callers compare it).
	if got := cleanErrorCode("invalid_grant"); got != "invalid_grant" {
		t.Errorf("cleanErrorCode(invalid_grant) = %q", got)
	}
}

// In a headless login the submitted MFA code can come back in a token error.
func TestLoginRedactsSubmittedSecretsInTokenErrors(t *testing.T) {
	l := &loginClient{secrets: []string{"123456"}}
	err := l.redactErr(&Error{Op: "token exchange", Status: 400, Code: "invalid_grant", Description: "bad 123456", Body: "123456"})
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != "invalid_grant" || strings.Contains(err.Error(), "123456") || strings.Contains(ae.Body, "123456") {
		t.Errorf("err = %v (%+v)", err, ae)
	}
	plain := l.redactErr(fmt.Errorf("Post x: bad status 123456: %w", context.DeadlineExceeded))
	if strings.Contains(plain.Error(), "123456") || !errors.Is(plain, context.DeadlineExceeded) {
		t.Errorf("plain error: %v", plain)
	}
}

func TestRedirectHostIsCaseInsensitive(t *testing.T) {
	cfg := Production
	cfg.RedirectURI = "myapp://OAUTH"
	if !cfg.isAppRedirect("myapp://oauth?code=c") || !cfg.isAppRedirect("MYAPP://Oauth?code=c") {
		t.Error("hostnames and schemes are case-insensitive")
	}
	if cfg.isAppRedirect("myapp://oauth.evil?code=c") {
		t.Error("a different host was accepted")
	}
}

// The submitted MFA code or password must not come back out of a failing
// token exchange at the end of a headless login.
func TestHeadlessLoginErrorsDoNotEchoSubmittedSecrets(t *testing.T) {
	t.Run("mfa code", func(t *testing.T) {
		f := newFake(t)
		c := start(t, f)
		f.tokenEcho = testCode
		_, err := CompleteLogin(context.Background(), f.cfg(), c, testCode)
		var ae *Error
		if !errors.As(err, &ae) || ae.Code != "invalid_grant" {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(err.Error(), testCode) || strings.Contains(ae.Description, testCode) {
			t.Errorf("error echoes the code: %v", err)
		}
	})
	t.Run("password", func(t *testing.T) {
		f := newFake(t)
		f.loginMode = "redirect"
		f.tokenEcho = testPassword
		_, err := StartLogin(context.Background(), f.cfg(), testEmail, testPassword)
		var ae *Error
		if !errors.As(err, &ae) {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(err.Error(), testPassword) || strings.Contains(ae.Description, testPassword) {
			t.Errorf("error echoes the password: %v", err)
		}
	})
}

// A failure while reading the body quotes what the server sent (a malformed
// chunked trailer here).
func TestBodyReadErrorsAreRedacted(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 4096)
			_, _ = c.Read(buf)
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X\r\n\r\n0\r\nhunter2-secret\r\n\r\n"))
			_ = c.Close()
		}
	}()
	cfg := Production.withDefaults()
	cfg.AccountsURL = "http://" + ln.Addr().String()
	l, err := newLoginClient(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	l.secrets = []string{"hunter2-secret"}
	u, _ := url.Parse(cfg.AccountsURL + "/next")
	_, err = l.send(context.Background(), http.MethodGet, u, nil)
	if err == nil {
		t.Fatal("want an error from the malformed trailer")
	}
	if strings.Contains(err.Error(), "hunter2-secret") {
		t.Errorf("body-read error quotes the secret: %v", err)
	}
	if errors.Unwrap(err) == nil {
		t.Error("the original cause was dropped")
	}
}

// Replacing net/http's *url.Error must not change how callers classify
// timeouts and cancellations.
func TestTransportErrorKeepsNetErrorBehaviour(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer slow.Close()
	cfg := Production.withDefaults()
	cfg.AccountsURL = slow.URL
	l, err := newLoginClient(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(slow.URL + "/x")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = l.send(ctx, http.MethodGet, u, nil)
	var ne net.Error
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &ne) || !ne.Timeout() {
		t.Errorf("deadline: Is=%v As=%v err=%v", errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne), err)
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	_, err = l.send(ctx2, http.MethodGet, u, nil)
	if !errors.Is(err, context.Canceled) || !errors.As(err, &ne) || ne.Timeout() {
		t.Errorf("cancel: Is=%v As=%v err=%v (a *url.Error was a net.Error, not a timeout)", errors.Is(err, context.Canceled), errors.As(err, &ne), err)
	}
}

// A secret echoed behind padding must not survive the cut to 200 bytes.
func TestPaddedEchoOfLoginSecrets(t *testing.T) {
	pad := strings.Repeat(" ", 192)
	t.Run("mfa code", func(t *testing.T) {
		f := newFake(t)
		c := start(t, f)
		f.tokenEcho = pad + testCode
		_, err := CompleteLogin(context.Background(), f.cfg(), c, testCode)
		var ae *Error
		if !errors.As(err, &ae) {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(ae.Description, "1234") || strings.Contains(ae.Body, "1234") || strings.Contains(err.Error(), "1234") {
			t.Errorf("part of the code survived: %+v", ae)
		}
	})
	t.Run("password", func(t *testing.T) {
		f := newFake(t)
		f.loginMode = "redirect"
		f.tokenEcho = pad + testPassword
		_, err := StartLogin(context.Background(), f.cfg(), testEmail, testPassword)
		var ae *Error
		if !errors.As(err, &ae) {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(ae.Description, "hunt") || strings.Contains(ae.Body, "hunt") || strings.Contains(err.Error(), "hunt") {
			t.Errorf("part of the password survived: %+v", ae)
		}
	})
}

func TestLogoutErrorDropsTheToken(t *testing.T) {
	const apiToken = "api-token-123"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, strings.Repeat(" ", 195)+apiToken)
	}))
	defer srv.Close()
	cfg := Production.withDefaults()
	cfg.AccountsURL, cfg.APIURL = srv.URL, srv.URL
	err := Logout(context.Background(), cfg, apiToken)
	var ae *Error
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(ae.Body, "api-") || strings.Contains(ae.Body, "123") {
		t.Errorf("Logout error keeps the token: %q", ae.Body)
	}
}

// The OAuth leg of a headless login reports operation, status and an
// allowlisted code, nothing the server said: pattern matching cannot make
// reflected text safe (JSON escapes, a secret from an earlier call, a token
// short enough to look harmless).
func TestOAuthLegReflectsNothing(t *testing.T) {
	const escapedPassword = `hunter2\u002dsecret` // JSON for hunter2-secret
	t.Run("regions error echoing the password, JSON-escaped", func(t *testing.T) {
		f := newFake(t)
		f.loginMode = "redirect"
		f.regionsEcho = `{"echo":"` + escapedPassword + `","token":"short-access"}`
		_, err := StartLogin(context.Background(), f.cfg(), testEmail, testPassword)
		var ae *Error
		if !errors.As(err, &ae) || ae.Status != http.StatusInternalServerError {
			t.Fatalf("err = %v", err)
		}
		if ae.Body != "" || ae.Description != "" || strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "short-access") {
			t.Errorf("the error reflects the response: %q / %+v", err, ae)
		}
	})
	t.Run("a later call that never saw the password", func(t *testing.T) {
		f := newFake(t)
		c := start(t, f)
		f.regionsEcho = testPassword + " " + testEmail
		_, err := CompleteLogin(context.Background(), f.cfg(), c, testCode)
		if err == nil || strings.Contains(err.Error(), testPassword) || strings.Contains(err.Error(), testEmail) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("token endpoint redirect carrying the authorization code", func(t *testing.T) {
		f := newFake(t)
		f.loginMode = "redirect"
		f.tokenRedirect = "http://127.0.0.1:1/?code=AUTHCODE"
		_, err := StartLogin(context.Background(), f.cfg(), testEmail, testPassword)
		if err == nil || strings.Contains(err.Error(), "AUTHCODE") || strings.Contains(err.Error(), "127.0.0.1:1") {
			t.Errorf("err = %v", err)
		}
		var ne net.Error
		if !errors.As(err, &ne) {
			t.Errorf("the connection failure is no longer a net.Error: %v", err)
		}
	})
	t.Run("malformed trailer on the token endpoint", func(t *testing.T) {
		ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X\r\n\r\n0\r\nAUTHCODE\r\n\r\n"))
				_ = c.Close()
			}
		}()
		cfg := Production.withDefaults()
		cfg.AccountsURL, cfg.APIURL = "http://"+ln.Addr().String(), "http://"+ln.Addr().String()
		_, _, err = postToken(context.Background(), cfg, "token exchange", url.Values{"code": {"AUTHCODE"}})
		if err == nil {
			t.Fatal("want an error")
		}
		l := &loginClient{}
		got := l.redactErr(err)
		if strings.Contains(got.Error(), "AUTHCODE") || errors.Unwrap(got) == nil {
			t.Errorf("redactErr = %v", got)
		}
	})
}

// Page text in a changed-flow error is kept (it is what makes the change
// diagnosable) but emails and long digit runs are masked, also in calls that
// were never given the email.
func TestPageExcerptMasksEmailsAndNumbers(t *testing.T) {
	f := newFake(t)
	f.pickerMode = "echo"
	c := start(t, f)
	err := SwitchMFAMethod(context.Background(), f.cfg(), c, MFASMS)
	if !errors.Is(err, ErrLoginFlowChanged) {
		t.Fatalf("err = %v", err)
	}
	for _, leak := range []string{testEmail, "12345678", testCode} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("excerpt keeps %q: %v", leak, err)
		}
	}
	if !strings.Contains(err.Error(), "Error for") {
		t.Errorf("the page text is gone: %v", err)
	}
}

func TestDecodeErrorDoesNotQuoteTheState(t *testing.T) {
	var c MFAChallenge
	err := c.UnmarshalBinary([]byte(`{"version":3,"created_at":"hunter2-secret"}`))
	if err == nil || strings.Contains(err.Error(), "hunter2-secret") {
		t.Errorf("err = %v", err)
	}
	if errors.Unwrap(err) == nil {
		t.Error("the cause was dropped")
	}
}

func TestExcerptNeverShowsRawMarkup(t *testing.T) {
	l := &loginClient{}
	// Embedded application state is not visible text.
	err := l.flowChanged("login page", &response{status: 500, body: `<script type="application/json">{"name":"Jane Resident","token":"short-access"}</script>`})
	for _, leak := range []string{"Jane", "short-access", "<script"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("excerpt shows %q: %v", leak, err)
		}
	}
	if !strings.Contains(err.Error(), "(no visible text)") {
		t.Errorf("want the placeholder: %v", err)
	}
	// A form action that does not parse is not shown, query included.
	err = l.flowChanged("login page", &response{status: 500, body: `<form action="/%zz?code=AUTHCODE"></form>`})
	if strings.Contains(err.Error(), "AUTHCODE") || !strings.Contains(err.Error(), "(invalid action)") {
		t.Errorf("err = %v", err)
	}
	// A valid action keeps only its path.
	err = l.flowChanged("login page", &response{status: 500, body: `<form action="/login/x?code=AUTHCODE"></form><p>hello</p>`})
	if strings.Contains(err.Error(), "AUTHCODE") || !strings.Contains(err.Error(), "forms: /login/x") || !strings.Contains(err.Error(), "hello") {
		t.Errorf("err = %v", err)
	}
}

// The public helpers scrub the token they were called with also when the
// server echoes it the way JSON serializers write it ("/" as "\/").
func TestPublicHelpersScrubJSONEscapedTokens(t *testing.T) {
	const tok = "short/access+token"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(w, `{"echo":"short\/access+token","u":"short\u002faccess+token"}`)
	}))
	defer srv.Close()
	cfg := Production.withDefaults()
	cfg.AccountsURL, cfg.APIURL = srv.URL, srv.URL
	ctx := context.Background()
	_, regionsErr := Regions(ctx, cfg, tok)
	_, denizenErr := DenizenLogin(ctx, cfg, tok)
	logoutErr := Logout(ctx, cfg, tok)
	for name, err := range map[string]error{"regions": regionsErr, "denizen": denizenErr, "logout": logoutErr} {
		var ae *Error
		if !errors.As(err, &ae) {
			t.Errorf("%s: err = %v", name, err)
			continue
		}
		if strings.Contains(ae.Body, "access") || strings.Contains(ae.Body, "token") {
			t.Errorf("%s: the escaped token survived: %q", name, ae.Body)
		}
	}
}

func TestMaskingOfPhoneNumbers(t *testing.T) {
	l := &loginClient{}
	for _, in := range []string{"call (555) 555-0100 now", "call +1 555-555-0100 now", "call 555.555.0100 now", "call 5555550100 now"} {
		got := l.redact(in)
		if strings.Contains(got, "0100") || strings.Contains(got, "555") {
			t.Errorf("redact(%q) = %q", in, got)
		}
	}
	for _, keep := range []string{"sent to your phone number ******9736", "updated 2026-11-12", "HTTP 500"} {
		if got := l.redact(keep); got != keep {
			t.Errorf("redact(%q) = %q, want it unchanged", keep, got)
		}
	}
}

// Text the user does not see (templates, hidden elements, noscript fallbacks)
// can hold embedded application data and is left out of the excerpt.
func TestExcerptSkipsInertContent(t *testing.T) {
	l := &loginClient{}
	for name, body := range map[string]string{
		"template": `<template id="resident">{"name":"Jane Resident","token":"short-access"}</template>`,
		"hidden":   `<div hidden>Jane Resident short-access</div>`,
		"display":  `<div style="display: none">Jane Resident short-access</div>`,
		"noscript": `<noscript><div>Jane Resident short-access</div></noscript>`,
		"nested":   `<div hidden><p><span>Jane Resident short-access</span></p></div>`,
	} {
		err := l.flowChanged("login page", &response{status: 500, body: body + `<p>Sign in</p>`})
		for _, leak := range []string{"Jane", "short-access", "<div", "<p"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%s: the excerpt shows %q: %v", name, leak, err)
			}
		}
		if !strings.Contains(err.Error(), "Sign in") {
			t.Errorf("%s: the visible text is gone: %v", name, err)
		}
	}
}

// JSON that does not decode cannot be scrubbed reliably (escapes), so it is
// not shown: duplicate keys, and a body cut at the read limit.
func TestUndecodableJSONBodiesAreNotShown(t *testing.T) {
	const tok = "short/access+token"
	ctx := context.Background()
	if got := scrubTo(ctx, `{"echo":"short\/access+token","x":1,"x":2}`, 200, tok); strings.Contains(got, "access") {
		t.Errorf("duplicate keys: %q", got)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(w, `{"echo":"short\/access+token","padding":"`+strings.Repeat(" ", maxBody))
	}))
	defer srv.Close()
	cfg := Production.withDefaults()
	cfg.AccountsURL, cfg.APIURL = srv.URL, srv.URL
	for name, err := range map[string]error{
		"regions": func() error { _, e := Regions(ctx, cfg, tok); return e }(),
		"denizen": func() error { _, e := DenizenLogin(ctx, cfg, tok); return e }(),
		"logout":  Logout(ctx, cfg, tok),
	} {
		var ae *Error
		if !errors.As(err, &ae) {
			t.Errorf("%s: err = %v", name, err)
			continue
		}
		if strings.Contains(ae.Body, "access") {
			t.Errorf("%s: the cut-off body shows the token: %q", name, ae.Body)
		}
	}
	// Plain text and decodable JSON are still shown.
	if got := scrubTo(ctx, "upstream timeout", 200, tok); got != "upstream timeout" {
		t.Errorf("plain text = %q", got)
	}
	if got := scrubTo(ctx, `{"error":"bad_gateway"}`, 200, tok); !strings.Contains(got, "bad_gateway") {
		t.Errorf("decodable JSON = %q", got)
	}
}

// Digit and phone masking must not split a long token and leave fragments.
func TestLongTokensAreMaskedWhole(t *testing.T) {
	l := &loginClient{}
	const hex = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	got := l.redact("Reference: " + hex)
	if got != "Reference: [redacted]" {
		t.Errorf("redact = %q", got)
	}
}

func TestLongEmailLocalPartIsMaskedWhole(t *testing.T) {
	l := &loginClient{}
	got := l.redact("for john.smith+" + strings.Repeat("a", 45) + "@example.com please")
	if got != "for [email] please" {
		t.Errorf("redact = %q", got)
	}
}
