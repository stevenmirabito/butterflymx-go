// Command bmx is a developer CLI for the unofficial ButterflyMX resident API
// client. It supports exploring API behavior through the probe command.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/stevenmirabito/butterflymx-go"
	"github.com/stevenmirabito/butterflymx-go/auth"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv)
	stop()
	os.Exit(code)
}

const usageText = `bmx - developer CLI for the unofficial ButterflyMX resident API

Usage: bmx [global flags] <command> [args]

Global flags:
  --env NAME           production (default), production-eu, staging, sandbox
                       Without --env or a URL override, the region saved in the
                       token (login stores it) picks production or production-eu.
  --accounts-url URL   override the accounts (OAuth) base URL
  --api-url URL        override the API base URL
  --unlock-url URL     override the unlock service base URL
  --token-file PATH    token file (default $XDG_CONFIG_HOME/bmx/token.json)
  --json               machine-readable output
  -v                   debug logging to stderr

Commands:
  login [--email E] [--mfa-method app|sms|email] [--code C]
        [--password-stdin] [--browser]
  logout
  whoami
  tenants
  doors [--tenant ID]
  unlock --door ID|NAME [--tenant ID]
  passes list [--status active|expired] [--kind custom,recurring,delivery_pass]
  passes get ID
  passes create --name N --door D... (--start T --end T | --weekdays mon,wed
                --from 09:00 --to 17:00 --start-date D --end-date D) --to RECIPIENT...
  passes delete ID
  keys add PASS --to RECIPIENT...
  keys revoke PASS KEY
  delivery create [--name N]   (always covers every guest-pass door)
  delivery rename ID NAME
  delivery extend ID [--days 30]
  history doors|calls|messages [--limit 20]
  raw graphql --op NAME (--query Q | --query-file F) [--vars JSON]
  raw rest METHOD PATH [--body JSON]
  probe [--allow-mutations] [--to EMAIL] [only:<name>...]
        probes: token statuses qr validation

A RECIPIENT is an email address or phone number, optionally "Name=address".
Passwords are read from BMX_PASSWORD, --password-stdin or a prompt; the
two-factor code from --code, BMX_TOTP_CODE or a prompt.

Two-factor login: without --mfa-method the server uses the method of your last
login (authenticator app, text message or email). Choosing sms or email makes
the server send a code. At the code prompt type "resend" for another code, or
"sms", "email" or "app" to verify another way. --code and BMX_TOTP_CODE skip
the prompt and are used as is; they cannot ask for a code to be sent, so with
sms or email run "bmx login --mfa-method sms" and answer the prompt on stdin.

Exit codes: 0 ok, 1 runtime error, 2 usage error.
`

// usageError marks a mistake in the command line (exit code 2).
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error { return &usageError{fmt.Sprintf(format, args...)} }

// errHelp is returned after help was printed (exit code 0).
var errHelp = errors.New("help requested")

var errNotLoggedIn = errors.New("not logged in")

type app struct {
	ctx    context.Context
	in     *bufio.Reader
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	getenv func(string) string

	json      bool
	verbose   bool
	envName   string
	tokenFile string

	// benv is the environment selected by --env and the URL overrides, and
	// acfg is its auth configuration (always benv.AuthConfig()). When
	// envExplicit is false, commands that use a saved token take the
	// environment of the token's region instead (see environmentFor).
	benv        butterflymx.Environment
	acfg        auth.Config
	envExplicit bool
	store       *auth.FileTokenStore

	tenants []butterflymx.Tenant
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, env func(string) string) int {
	a := &app{ctx: ctx, stdin: stdin, in: bufio.NewReader(stdin), stdout: stdout, stderr: stderr, getenv: env}
	err := a.dispatch(args)
	switch {
	case err == nil, errors.Is(err, errHelp):
		return 0
	}
	var ue *usageError
	if errors.As(err, &ue) {
		_, _ = fmt.Fprintf(stderr, "bmx: %v\n(run `bmx help` for usage)\n", ue)
		return 2
	}
	_, _ = fmt.Fprintf(stderr, "bmx: %s\n", describeErr(err))
	return 1
}

func (a *app) dispatch(args []string) error {
	fs := flag.NewFlagSet("bmx", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var accountsURL, apiURL, unlockURL string
	fs.StringVar(&a.envName, "env", "", "")
	fs.StringVar(&accountsURL, "accounts-url", "", "")
	fs.StringVar(&apiURL, "api-url", "", "")
	fs.StringVar(&unlockURL, "unlock-url", "", "")
	fs.StringVar(&a.tokenFile, "token-file", "", "")
	fs.BoolVar(&a.json, "json", false, "")
	fs.BoolVar(&a.verbose, "v", false, "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprint(a.stdout, usageText)
			return errHelp
		}
		return usagef("%v", err)
	}
	rest := fs.Args()
	if len(rest) == 0 {
		_, _ = fmt.Fprint(a.stderr, usageText)
		return usagef("no command given")
	}
	if rest[0] == "help" {
		_, _ = fmt.Fprint(a.stdout, usageText)
		return errHelp
	}
	if err := a.setupEnv(accountsURL, apiURL, unlockURL); err != nil {
		return err
	}
	cmd, rest := rest[0], rest[1:]
	switch cmd {
	case "login":
		return a.cmdLogin(rest)
	case "logout":
		return a.cmdLogout(rest)
	case "whoami":
		return a.cmdWhoami(rest)
	case "tenants":
		return a.cmdTenants(rest)
	case "doors":
		return a.cmdDoors(rest)
	case "unlock":
		return a.cmdUnlock(rest)
	case "passes":
		return a.cmdPasses(rest)
	case "keys":
		return a.cmdKeys(rest)
	case "delivery":
		return a.cmdDelivery(rest)
	case "history":
		return a.cmdHistory(rest)
	case "raw":
		return a.cmdRaw(rest)
	case "probe":
		return a.cmdProbe(rest)
	}
	return usagef("unknown command %q", cmd)
}

func (a *app) setupEnv(accountsURL, apiURL, unlockURL string) error {
	a.envExplicit = a.envName != "" || accountsURL != "" || apiURL != "" || unlockURL != ""
	var env butterflymx.Environment
	switch a.envName {
	case "", "production":
		env = butterflymx.Production
	case "production-eu":
		env = butterflymx.ProductionEU
	case "staging":
		env = butterflymx.Staging
	case "sandbox":
		env = butterflymx.Sandbox
	default:
		return usagef("unknown --env %q (production, production-eu, staging, sandbox)", a.envName)
	}
	if accountsURL != "" {
		env.AccountsURL = strings.TrimRight(accountsURL, "/")
	}
	if apiURL != "" {
		env.APIURL = strings.TrimRight(apiURL, "/")
		// Never send an unlock to the real service while the API is
		// redirected; the caller must opt in with --unlock-url.
		env.UnlockURL = ""
	}
	if unlockURL != "" {
		env.UnlockURL = strings.TrimRight(unlockURL, "/")
	}
	a.benv, a.acfg = env, env.AuthConfig()
	if a.tokenFile == "" {
		dir := a.getenv("XDG_CONFIG_HOME")
		if dir == "" {
			home := a.getenv("HOME")
			if home == "" {
				var err error
				if home, err = os.UserHomeDir(); err != nil {
					return fmt.Errorf("cannot locate a token file, use --token-file: %w", err)
				}
			}
			dir = filepath.Join(home, ".config")
		}
		a.tokenFile = filepath.Join(dir, "bmx", "token.json")
	}
	a.store = auth.NewFileTokenStore(a.tokenFile)
	return nil
}

func (a *app) logger() *slog.Logger {
	if !a.verbose {
		return nil
	}
	return slog.New(slog.NewTextHandler(a.stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// environmentFor returns the environment to use with the saved token tok.
// An explicit --env or URL override always wins. Otherwise the token's region
// selects the production environment of that region, so an EU account works
// without flags; a token without a region keeps the default.
func (a *app) environmentFor(tok *auth.Token) (butterflymx.Environment, error) {
	if a.envExplicit || tok == nil || tok.Region == "" {
		return a.benv, nil
	}
	env, err := butterflymx.EnvironmentForRegion(tok.Region)
	if err != nil {
		return a.benv, fmt.Errorf("%w (the saved token has region %q; pass --env to choose an environment)", err, tok.Region)
	}
	return env, nil
}

// authenticator builds an Authenticator for env that refreshes and persists
// the stored token.
func (a *app) authenticator(env butterflymx.Environment) *auth.Authenticator {
	return auth.NewAuthenticator(auth.AuthenticatorConfig{Config: env.AuthConfig(), Store: a.store, Logger: a.logger()})
}

// client builds an API client that refreshes and persists the stored token.
func (a *app) client() (*butterflymx.Client, error) { return a.newClient(false) }

// newClient is client with the option to turn off the library's own request
// validation (only for the probes that observe the server's answers).
func (a *app) newClient(skipValidation bool) (*butterflymx.Client, error) {
	tok, err := a.store.Load(a.ctx)
	if err != nil {
		return nil, err
	}
	if tok == nil {
		return nil, errNotLoggedIn
	}
	env, err := a.environmentFor(tok)
	if err != nil {
		return nil, err
	}
	return butterflymx.New(butterflymx.Options{
		Environment: env, Auth: a.authenticator(env), Logger: a.logger(), SkipClientValidation: skipValidation,
	})
}

// describeErr turns library errors into short messages.
func describeErr(err error) string {
	switch {
	case errors.Is(err, errNotLoggedIn), errors.Is(err, auth.ErrReauthRequired):
		return "not logged in: run `bmx login`"
	case errors.Is(err, butterflymx.ErrUnauthorized):
		return "unauthorized, the session was rejected: run `bmx login`"
	case errors.Is(err, auth.ErrInvalidCredentials):
		return "login failed: invalid email or password"
	case errors.Is(err, auth.ErrInvalidMFACode):
		return "login failed: invalid two-factor code"
	case errors.Is(err, auth.ErrMFAResendUnsupported):
		return "login failed: the authenticator app has no code to resend"
	case errors.Is(err, auth.ErrMFAExpired):
		return "login failed: the two-factor challenge expired, try again"
	case errors.Is(err, butterflymx.ErrNotSupported):
		return err.Error() + " (is --unlock-url set for this environment?)"
	}
	return err.Error()
}

// ---- flag helpers ----

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// parse parses flags interspersed with positional arguments and checks the
// number of positionals.
func (a *app) parse(name string, fs *flag.FlagSet, args []string, minPos, maxPos int) ([]string, error) {
	fs.SetOutput(io.Discard)
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				_, _ = fmt.Fprintf(a.stdout, "Usage of bmx %s:\n", name)
				fs.SetOutput(a.stdout)
				fs.PrintDefaults()
				return nil, errHelp
			}
			return nil, usagef("%s: %v", name, err)
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	if len(pos) < minPos || (maxPos >= 0 && len(pos) > maxPos) {
		return nil, usagef("%s: wrong number of arguments (%d)", name, len(pos))
	}
	return pos, nil
}

func (a *app) flagset(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ContinueOnError)
}

// ---- output helpers ----

func (a *app) emitJSON(v any) error {
	enc := json.NewEncoder(a.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (a *app) table(header []string, rows [][]string) {
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, strings.Join(header, "\t"))
	for _, r := range rows {
		_, _ = fmt.Fprintln(tw, strings.Join(r, "\t"))
	}
	_ = tw.Flush()
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04 MST")
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
