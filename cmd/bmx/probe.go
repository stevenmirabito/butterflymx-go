package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/stevenmirabito/butterflymx-go"
)

// Probe outcomes.
const (
	outOK         = "ok"
	outSkipped    = "skipped"
	outFailed     = "failed"
	outUnexpected = "UNEXPECTED"
)

type probeKV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type probeResult struct {
	Name     string    `json:"name"`
	Question string    `json:"question"`
	Outcome  string    `json:"outcome"`
	Reason   string    `json:"reason,omitempty"`
	Details  []probeKV `json:"details,omitempty"`
}

func (r *probeResult) add(k, format string, args ...any) {
	r.Details = append(r.Details, probeKV{k, fmt.Sprintf(format, args...)})
}

func (r *probeResult) skip(format string, args ...any) {
	r.Outcome, r.Reason = outSkipped, fmt.Sprintf(format, args...)
}

func (r *probeResult) fail(format string, args ...any) {
	r.Outcome, r.Reason = outFailed, fmt.Sprintf(format, args...)
}

type probeCtx struct {
	a         *app
	c         *butterflymx.Client
	tenantRef string
	to        string

	tenantOnce bool
	tenant     butterflymx.Tenant
	aps        []butterflymx.AccessPoint
	tenantErr  error
}

func (p *probeCtx) load() error {
	if !p.tenantOnce {
		p.tenantOnce = true
		p.tenant, p.aps, p.tenantErr = p.a.tenantAndDoors(p.c, p.tenantRef)
	}
	return p.tenantErr
}

type probeDef struct {
	name, question string
	mutating       bool
	needsTo        bool
	run            func(ctx context.Context, p *probeCtx, r *probeResult)
}

var probes = []probeDef{
	{name: "token", question: "Q2: API token age and expiry", run: probeToken},
	{name: "statuses", question: "Q6: which filter[status] values exist", run: probeStatuses},
	{name: "qr", question: "Q14: are QR images readable without auth", run: probeQR},
	{name: "validation", question: "Q9/Q13: error shape and duration limits", mutating: true, needsTo: true, run: probeValidation},
}

func (a *app) cmdProbe(args []string) error {
	fs := a.flagset("probe")
	allow := fs.Bool("allow-mutations", false, "run the probes that create (and then delete) passes")
	to := fs.String("to", "", "recipient (email or phone) for probes that create passes")
	tenant := fs.String("tenant", "", "tenant ID")
	pos, err := a.parse("probe", fs, args, 0, -1)
	if err != nil {
		return err
	}
	var only []string
	for _, s := range pos {
		n := strings.TrimPrefix(s, "only:")
		if !slices.ContainsFunc(probes, func(d probeDef) bool { return d.name == n }) {
			return usagef("probe: unknown probe %q", s)
		}
		only = append(only, n)
	}
	if *to != "" {
		if _, err := parseRecipients([]string{*to}); err != nil {
			return err
		}
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	p := &probeCtx{a: a, c: c, tenantRef: *tenant, to: *to}

	var results []probeResult
	failed := false
	for _, d := range probes {
		if len(only) > 0 && !slices.Contains(only, d.name) {
			continue
		}
		r := probeResult{Name: d.name, Question: d.question, Outcome: outOK}
		switch {
		case d.mutating && !*allow:
			r.skip("mutating probe: pass --allow-mutations")
		case d.needsTo && *to == "":
			r.skip("needs --to <recipient> (a real address may receive a message)")
		default:
			d.run(a.ctx, p, &r)
		}
		failed = failed || r.Outcome == outFailed
		results = append(results, r)
	}
	if a.json {
		if err := a.emitJSON(results); err != nil {
			return err
		}
	} else {
		for _, r := range results {
			a.printProbe(r)
		}
	}
	if failed {
		return errors.New("one or more probes failed")
	}
	return nil
}

func (a *app) printProbe(r probeResult) {
	_, _ = fmt.Fprintf(a.stdout, "== %s (%s)\n", r.Name, r.Question)
	switch r.Outcome {
	case outOK:
	case outSkipped:
		_, _ = fmt.Fprintf(a.stdout, "   SKIPPED: %s\n", r.Reason)
	default:
		_, _ = fmt.Fprintf(a.stdout, "   %s: %s\n", strings.ToUpper(r.Outcome), r.Reason)
	}
	for _, kv := range r.Details {
		_, _ = fmt.Fprintf(a.stdout, "   %-26s %s\n", kv.Key+":", kv.Value)
	}
	_, _ = fmt.Fprintln(a.stdout)
}

// httpStatus extracts the HTTP status from a library error (0 if none).
func httpStatus(err error) int {
	var e *butterflymx.Error
	if errors.As(err, &e) {
		return e.StatusCode
	}
	return 0
}

func errBody(err error, n int) string {
	var e *butterflymx.Error
	if errors.As(err, &e) {
		return truncate(string(e.Body), n)
	}
	return ""
}

// ---- read-only probes ----

func probeToken(ctx context.Context, p *probeCtx, r *probeResult) {
	tok, err := p.a.store.Load(ctx)
	if err != nil || tok == nil {
		r.fail("cannot read the stored token")
		return
	}
	now := time.Now()
	if tok.APITokenIssuedAt.IsZero() {
		r.add("api_token_age", "unknown (no issue time stored)")
	} else {
		r.add("api_token_issued_at", "%s", tok.APITokenIssuedAt.UTC().Format(time.RFC3339))
		r.add("api_token_age", "%s", now.Sub(tok.APITokenIssuedAt).Round(time.Second))
	}
	if tok.Expiry.IsZero() {
		r.add("oauth_expiry", "unknown")
	} else {
		r.add("oauth_expiry", "%s (in %s)", tok.Expiry.UTC().Format(time.RFC3339), tok.Expiry.Sub(now).Round(time.Second))
	}
	r.add("has_refresh_token", "%v", tok.RefreshToken != "")
	r.add("has_api_token", "%v", tok.APIToken != "")
	if _, err := p.c.CurrentUser(ctx); err != nil {
		r.add("current_user_call", "FAILED: %s (HTTP %d)", describeErr(err), httpStatus(err))
		r.fail("the token does not work")
		return
	}
	r.add("current_user_call", "ok, token still works")
}

func probeStatuses(ctx context.Context, p *probeCtx, r *probeResult) {
	if err := p.load(); err != nil {
		r.skip("no tenant: %s", describeErr(err))
		return
	}
	tid, err := p.tenant.ID.As(butterflymx.TypeTenant)
	if err != nil {
		r.fail("%v", err)
		return
	}
	// Counts alone can't tell a real filter from a value the server ignores, so
	// collect the full ID set per value (paging through up to 25 pages) and
	// compare the sets with each other and with active ∪ expired.
	type passSet struct {
		ids    map[string]bool
		future int // passes whose starts_at is still in the future
		err    string
	}
	now := time.Now()
	fetch := func(st string) passSet {
		ps := passSet{ids: map[string]bool{}}
		for page := 1; page <= 25; page++ {
			var doc struct {
				Data []struct {
					ID         string `json:"id"`
					Attributes struct {
						StartsAt string `json:"starts_at"`
					} `json:"attributes"`
				} `json:"data"`
				Links struct {
					Next *string `json:"next"`
				} `json:"links"`
			}
			q := url.Values{"filter[tenant]": {tid.String()}, "filter[status]": {st}, "page[size]": {"20"}, "page[number]": {fmt.Sprint(page)}}
			if err := p.c.REST(ctx, http.MethodGet, "/v3/access_codes", q, nil, &doc); err != nil {
				if s := httpStatus(err); s != 0 {
					ps.err = fmt.Sprintf("HTTP %d %s", s, errBody(err, 200))
				} else {
					ps.err = fmt.Sprintf("error: %v", err)
				}
				return ps
			}
			for _, d := range doc.Data {
				ps.ids[d.ID] = true
				if t, err := time.Parse(time.RFC3339, d.Attributes.StartsAt); err == nil && t.After(now) {
					ps.future++
				}
			}
			if doc.Links.Next == nil || len(doc.Data) == 0 {
				break
			}
		}
		return ps
	}
	equal := func(a, b map[string]bool) bool {
		if len(a) != len(b) {
			return false
		}
		for id := range a {
			if !b[id] {
				return false
			}
		}
		return true
	}
	statuses := []string{"active", "expired", "upcoming", "all", "inactive"}
	sets := map[string]passSet{}
	for _, st := range statuses {
		sets[st] = fetch(st)
	}
	union := map[string]bool{}
	for _, st := range []string{"active", "expired"} {
		for id := range sets[st].ids {
			union[id] = true
		}
	}
	for _, st := range statuses {
		ps := sets[st]
		if ps.err != "" {
			r.add("status="+st, "%s", ps.err)
			continue
		}
		var same []string
		for _, other := range statuses {
			if other != st && sets[other].err == "" && equal(ps.ids, sets[other].ids) {
				same = append(same, other)
			}
		}
		rel := "distinct set"
		switch {
		case len(same) > 0:
			rel = "same set as " + strings.Join(same, ", ")
		case len(union) > 0 && equal(ps.ids, union):
			rel = "same set as active+expired"
		}
		r.add("status="+st, "%d passes (%d start in the future); %s", len(ps.ids), ps.future, rel)
	}
}

func probeQR(ctx context.Context, p *probeCtx, r *probeResult) {
	if err := p.load(); err != nil {
		r.skip("no tenant: %s", describeErr(err))
		return
	}
	ks, err := p.c.Keychains(ctx, p.tenant.ID, butterflymx.KeychainFilter{Status: butterflymx.StatusActive})
	if err != nil {
		r.fail("listing passes: %s", describeErr(err))
		return
	}
	qr := ""
	find := func(k butterflymx.Keychain) {
		for _, v := range k.VirtualKeys {
			if qr == "" && v.QRCodeURL != "" {
				qr = v.QRCodeURL
			}
		}
	}
	for _, k := range ks {
		find(k)
	}
	// The list may omit key details; read a few passes individually.
	for i, k := range ks {
		if qr != "" || i >= 5 {
			break
		}
		if full, err := p.c.Keychain(ctx, k.ID); err == nil {
			find(*full)
		}
	}
	if qr == "" {
		r.skip("no active pass with a key that has a qr_code_image_url")
		return
	}
	hc := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, qr, nil)
	if err != nil {
		r.fail("invalid QR image URL")
		return
	}
	resp, err := hc.Do(req) // deliberately no Authorization header
	if err != nil {
		// url.Error embeds the URL, which is a credential: print the cause only.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		r.fail("unauthenticated GET failed: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<20))
	r.add("unauthenticated_GET", "HTTP %d", resp.StatusCode)
	r.add("content_type", "%s", resp.Header.Get("Content-Type"))
	r.add("body_bytes", "%d", n)
	r.add("publicly_readable", "%v", resp.StatusCode == http.StatusOK)
}

// ---- mutating probes ----

// cleanup deletes a pass created by a probe, with a context that survives
// cancellation, and records a loud note when that fails.
func cleanup(parent context.Context, p *probeCtx, r *probeResult, id butterflymx.ID) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 30*time.Second)
	defer cancel()
	if err := p.c.DeleteKeychain(ctx, id); err != nil {
		r.add("CLEANUP FAILED", "pass %s was NOT deleted, delete it manually: %s", id, describeErr(err))
		r.fail("cleanup of pass %s failed", id)
		return
	}
	r.add("cleanup", "deleted pass %s", id)
}

func probeValidation(ctx context.Context, p *probeCtx, r *probeResult) {
	if err := p.load(); err != nil {
		r.skip("no tenant: %s", describeErr(err))
		return
	}
	recips, err := parseRecipients([]string{p.to})
	if err != nil {
		r.fail("%v", err)
		return
	}
	var vk, noVK []butterflymx.AccessPoint
	for _, ap := range p.aps {
		if ap.SupportsVirtualKeys() {
			vk = append(vk, ap)
		} else {
			noVK = append(noVK, ap)
		}
	}
	if len(vk) == 0 {
		r.skip("no door supports virtual keys")
		return
	}
	r.add("building_max_days", "%d (VirtualKeysDurationPeriod)", p.tenant.Building.VirtualKeysDurationPeriod)
	start := time.Now().Add(time.Hour).Truncate(time.Second)
	type tc struct {
		name       string
		aps        []butterflymx.AccessPoint
		start, end time.Time
	}
	cases := []tc{
		{"end_before_start", vk[:1], start, start.Add(-time.Hour)},
		{"duration_400_days", vk[:1], start, start.Add(400 * 24 * time.Hour)},
	}
	if len(noVK) > 0 {
		cases = append(cases, tc{"door_without_virtual_keys", noVK[:1], start, start.Add(time.Hour)})
	} else {
		r.add("door_without_virtual_keys", "skipped: every door supports virtual keys")
	}
	// The typed CreateKeychain on a client without pre-flight validation sends
	// what the library would normally refuse, so the server's answers show.
	raw, err := p.a.newClient(true)
	if err != nil {
		r.fail("%s", describeErr(err))
		return
	}
	for _, c := range cases {
		k, err := raw.CreateKeychain(ctx, butterflymx.CreateKeychainParams{
			TenantID:       p.tenant.ID,
			AccessPointIDs: doorIDs(c.aps),
			Name:           "bmx probe " + c.name,
			Schedule:       butterflymx.CustomSchedule{StartsAt: c.start, EndsAt: c.end},
			Recipients:     recips,
		})
		if err == nil {
			r.Outcome = outUnexpected
			r.add(c.name, "!!! ACCEPTED (expected a rejection), created pass %s", k.ID)
			if k.ID > 0 {
				cleanup(ctx, p, r, k.ID)
			}
			continue
		}
		if st := httpStatus(err); st != 0 {
			r.add(c.name, "HTTP %d %s", st, errBody(err, 400))
		} else {
			r.add(c.name, "transport error: %v", err)
		}
	}
	if r.Outcome == outUnexpected {
		r.Reason = "a create that should have been rejected succeeded (it was deleted again)"
	}
}
