package auth_test

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/stevenmirabito/butterflymx-go/auth"
	"github.com/stevenmirabito/butterflymx-go/butterflymxtest"
)

// Logging in takes two steps when the account has two-factor authentication
// enabled: StartLogin checks the password and returns a challenge, and
// CompleteLogin submits the code, which comes from an authenticator app, a
// text message or an email depending on the method. The server picks the first
// method (the one used by the last login); the sms example below shows how to
// ask for another. The challenge can be serialized between the steps, for
// example to hand it to a web handler that receives the code later. An
// Authenticator then keeps the resulting token fresh.
//
// This example runs against the in-memory fake in package butterflymxtest. A
// real program would use [auth.Production] and read the credentials and the
// code from the user.
func Example_login() {
	srv := butterflymxtest.NewServer()
	defer srv.Close()

	ctx := context.Background()
	cfg := auth.ConfigFor(srv.URL(), srv.URL())

	res, err := auth.StartLogin(ctx, cfg, butterflymxtest.DefaultEmail, butterflymxtest.DefaultPassword)
	if err != nil {
		log.Fatal(err)
	}
	if res.Challenge == nil {
		log.Fatal("expected a two-factor challenge")
	}
	fmt.Println("two-factor method:", res.Challenge.Method)

	// Park the challenge somewhere (it holds session cookies: keep it
	// private and short-lived) and restore it when the code arrives.
	blob, err := res.Challenge.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	var challenge auth.MFAChallenge
	if err := challenge.UnmarshalBinary(blob); err != nil {
		log.Fatal(err)
	}

	// A wrong code leaves the challenge usable.
	_, err = auth.CompleteLogin(ctx, cfg, &challenge, "000000")
	fmt.Println("wrong code rejected:", errors.Is(err, auth.ErrInvalidMFACode))

	tok, err := auth.CompleteLogin(ctx, cfg, &challenge, srv.CurrentTOTP())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("has API token:", tok.APIToken != "")

	// The Authenticator refreshes the OAuth token and re-runs the API token
	// exchange when needed, and persists every change in the store. Use an
	// auth.FileTokenStore to survive restarts. Pass the Authenticator as
	// butterflymx.Options.Auth.
	a := auth.NewAuthenticator(auth.AuthenticatorConfig{
		Config: cfg,
		Store:  auth.NewMemoryTokenStore(tok),
	})
	apiToken, err := a.APIToken(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("authenticator ready:", apiToken == tok.APIToken)

	// Output:
	// two-factor method: authenticator_app
	// wrong code rejected: true
	// has API token: true
	// authenticator ready: true
}

// Instead of the method the server picks, a login can ask for a text message
// (or an email) up front with WithMFAMethod, and the user can request another
// code if the first does not arrive. ParseMFAMethod accepts the words a user
// would type, such as "text" or "app".
//
// Choosing sms or email makes the server send the code, and
// MFAChallenge.Destination tells the user where to look (a masked phone number
// for sms; the email address is not shown). SwitchMFAMethod changes the method
// of a challenge that already exists, the "Verify another way" link.
//
// This example runs against the in-memory fake in package butterflymxtest,
// whose texts are read with srv.LastMFACode. A real program would read the code
// from the user.
func Example_mfaSMS() {
	srv := butterflymxtest.NewServer()
	defer srv.Close()

	ctx := context.Background()
	cfg := auth.ConfigFor(srv.URL(), srv.URL())

	method, err := auth.ParseMFAMethod("text")
	if err != nil {
		log.Fatal(err)
	}
	res, err := auth.StartLogin(ctx, cfg, butterflymxtest.DefaultEmail, butterflymxtest.DefaultPassword,
		auth.WithMFAMethod(method))
	if err != nil {
		log.Fatal(err)
	}
	challenge := res.Challenge
	if challenge == nil {
		log.Fatal("expected a two-factor challenge")
	}
	fmt.Println("two-factor method:", challenge.Method)
	fmt.Println("code sent to:", challenge.Destination)

	// Ask for another text; the earlier code keeps working.
	if challenge.CanResend() {
		if err := auth.ResendMFACode(ctx, cfg, challenge); err != nil {
			log.Fatal(err)
		}
		fmt.Println("code sent again")
	}

	tok, err := auth.CompleteLogin(ctx, cfg, challenge, srv.LastMFACode("sms"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("logged in:", tok.APIToken != "")

	// Output:
	// two-factor method: sms
	// code sent to: ******0100
	// code sent again
	// logged in: true
}
