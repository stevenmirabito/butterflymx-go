package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/stevenmirabito/butterflymx-go"
)

// ---- resolution of tenants and doors ----

// pickTenant selects the tenant named by ref (a global or numeric ID). With
// an empty ref the account's only tenant is used.
func (a *app) pickTenant(c *butterflymx.Client, ref string) (butterflymx.Tenant, error) {
	if a.tenants == nil {
		ts, err := c.Tenants(a.ctx)
		if err != nil {
			return butterflymx.Tenant{}, err
		}
		a.tenants = ts
	}
	ts := a.tenants
	if ref == "" {
		switch len(ts) {
		case 0:
			return butterflymx.Tenant{}, errors.New("the account has no tenants")
		case 1:
			return ts[0], nil
		}
		var names []string
		for _, t := range ts {
			names = append(names, fmt.Sprintf("%s (%s, %s)", t.ID, t.Unit.Label, t.Building.Name))
		}
		return butterflymx.Tenant{}, usagef("the account has %d tenants, choose one with --tenant: %s", len(ts), strings.Join(names, "; "))
	}
	for _, t := range ts {
		if t.ID.String() == ref || t.ID.Num.String() == ref {
			return t, nil
		}
	}
	return butterflymx.Tenant{}, fmt.Errorf("no tenant %q (see `bmx tenants`)", ref)
}

// resolveDoor finds one door by ID or by name (case-insensitive, exact match
// first, then substring).
func resolveDoor(aps []butterflymx.AccessPoint, ref string) (butterflymx.AccessPoint, error) {
	for _, ap := range aps {
		if ap.ID.String() == ref || ap.RESTID().String() == ref {
			return ap, nil
		}
	}
	var exact, partial []butterflymx.AccessPoint
	lref := strings.ToLower(strings.TrimSpace(ref))
	for _, ap := range aps {
		n := strings.ToLower(ap.Name)
		if n == lref {
			exact = append(exact, ap)
		} else if lref != "" && strings.Contains(n, lref) {
			partial = append(partial, ap)
		}
	}
	cands := exact
	if len(cands) == 0 {
		cands = partial
	}
	switch len(cands) {
	case 0:
		return butterflymx.AccessPoint{}, fmt.Errorf("no door matches %q (see `bmx doors`)", ref)
	case 1:
		return cands[0], nil
	}
	var parts []string
	for _, ap := range cands {
		parts = append(parts, fmt.Sprintf("%q (%s)", ap.Name, ap.ID))
	}
	return butterflymx.AccessPoint{}, fmt.Errorf("door %q is ambiguous, use an ID: %s", ref, strings.Join(parts, ", "))
}

func resolveDoors(aps []butterflymx.AccessPoint, refs []string) ([]butterflymx.AccessPoint, error) {
	var out []butterflymx.AccessPoint
	for _, r := range refs {
		ap, err := resolveDoor(aps, r)
		if err != nil {
			return nil, err
		}
		out = append(out, ap)
	}
	return out, nil
}

func doorIDs(aps []butterflymx.AccessPoint) []butterflymx.GlobalID {
	ids := make([]butterflymx.GlobalID, len(aps))
	for i, ap := range aps {
		ids[i] = ap.ID
	}
	return ids
}

// tenantAndDoors resolves the tenant and loads its doors.
func (a *app) tenantAndDoors(c *butterflymx.Client, tenantRef string) (butterflymx.Tenant, []butterflymx.AccessPoint, error) {
	t, err := a.pickTenant(c, tenantRef)
	if err != nil {
		return t, nil, err
	}
	aps, err := c.AccessPoints(a.ctx, t.ID)
	return t, aps, err
}

// ---- commands ----

func (a *app) cmdTenants(args []string) error {
	fs := a.flagset("tenants")
	if _, err := a.parse("tenants", fs, args, 0, 0); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	ts, err := c.Tenants(a.ctx)
	if err != nil {
		return err
	}
	if a.json {
		return a.emitJSON(ts)
	}
	rows := make([][]string, len(ts))
	for i, t := range ts {
		rows[i] = []string{t.ID.String(), t.Unit.Label, t.Building.Name, t.Building.TimeZone,
			fmt.Sprint(t.CanCreateGuestPasses()), fmt.Sprint(t.Building.VirtualKeysDurationPeriod)}
	}
	a.table([]string{"ID", "UNIT", "BUILDING", "TIMEZONE", "GUEST PASSES", "MAX DAYS"}, rows)
	return nil
}

func (a *app) cmdDoors(args []string) error {
	fs := a.flagset("doors")
	tenant := fs.String("tenant", "", "tenant ID (optional when the account has one tenant)")
	if _, err := a.parse("doors", fs, args, 0, 0); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	_, aps, err := a.tenantAndDoors(c, *tenant)
	if err != nil {
		return err
	}
	if a.json {
		return a.emitJSON(aps)
	}
	rows := make([][]string, len(aps))
	for i, ap := range aps {
		var devs []string
		for _, d := range ap.Devices {
			devs = append(devs, d.Name)
		}
		rows[i] = []string{ap.ID.String(), ap.Name, fmt.Sprint(ap.SupportsVirtualKeys()), fmt.Sprint(ap.Online), strings.Join(devs, ", ")}
	}
	a.table([]string{"ID", "NAME", "GUEST PASSES", "ONLINE", "DEVICES"}, rows)
	return nil
}

func (a *app) cmdUnlock(args []string) error {
	fs := a.flagset("unlock")
	door := fs.String("door", "", "door ID or name (required)")
	tenant := fs.String("tenant", "", "tenant ID")
	if _, err := a.parse("unlock", fs, args, 0, 0); err != nil {
		return err
	}
	if *door == "" {
		return usagef("unlock: --door is required")
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	t, aps, err := a.tenantAndDoors(c, *tenant)
	if err != nil {
		return err
	}
	ap, err := resolveDoor(aps, *door)
	if err != nil {
		return err
	}
	reqID, err := c.Unlock(a.ctx, t.ID, ap.ID)
	if err != nil {
		return err
	}
	if a.json {
		return a.emitJSON(map[string]any{"door": ap.Name, "door_id": ap.ID, "request_id": reqID})
	}
	_, _ = fmt.Fprintf(a.stdout, "Unlock requested for %q (request %s)\n", ap.Name, reqID)
	return nil
}

func (a *app) cmdHistory(args []string) error {
	fs := a.flagset("history")
	limit := fs.Int("limit", 20, "maximum number of entries")
	tenant := fs.String("tenant", "", "tenant ID")
	pos, err := a.parse("history", fs, args, 1, 1)
	if err != nil {
		return err
	}
	if *limit < 1 {
		return usagef("history: --limit must be positive")
	}
	if !slices.Contains([]string{"doors", "calls", "messages"}, pos[0]) {
		return usagef("history: unknown kind %q (doors, calls, messages)", pos[0])
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	t, err := a.pickTenant(c, *tenant)
	if err != nil {
		return err
	}
	var (
		items []any
		rows  [][]string
		head  []string
	)
	switch pos[0] {
	case "doors":
		head = []string{"TIME", "METHOD", "TYPE", "DOOR", "PLATE"}
		for r, err := range c.DoorReleases(a.ctx, t.ID) {
			if err != nil {
				return err
			}
			plate := ""
			if r.LicensePlate != nil {
				plate = r.LicensePlate.Number
			}
			items = append(items, r)
			rows = append(rows, []string{fmtTime(r.LoggedAt), r.Method, r.Type, r.AccessPoint.Name, plate})
			if len(items) >= *limit {
				break
			}
		}
	case "calls":
		head = []string{"TIME", "TYPE", "STATUS", "DEVICE"}
		for r, err := range c.Calls(a.ctx, t.ID) {
			if err != nil {
				return err
			}
			items = append(items, r)
			rows = append(rows, []string{fmtTime(r.LoggedAt), r.NotificationType, r.DisplayStatus, r.Device.Name})
			if len(items) >= *limit {
				break
			}
		}
	case "messages":
		head = []string{"TIME", "ORIGIN", "TITLE", "BODY"}
		for r, err := range c.Messages(a.ctx, t.ID, nil) {
			if err != nil {
				return err
			}
			items = append(items, r)
			rows = append(rows, []string{fmtTime(r.CreatedAt), r.Origin, truncate(r.Title, 30), truncate(r.Body, 50)})
			if len(items) >= *limit {
				break
			}
		}
	default:
		return usagef("history: unknown kind %q (doors, calls, messages)", pos[0])
	}
	if a.json {
		if items == nil {
			items = []any{}
		}
		return a.emitJSON(items)
	}
	if len(rows) == 0 {
		_, _ = fmt.Fprintln(a.stdout, "No entries.")
		return nil
	}
	a.table(head, rows)
	return nil
}

func (a *app) cmdRaw(args []string) error {
	if len(args) == 0 {
		return usagef("raw: expected graphql or rest")
	}
	switch args[0] {
	case "graphql":
		return a.rawGraphQL(args[1:])
	case "rest":
		return a.rawREST(args[1:])
	}
	return usagef("raw: unknown subcommand %q", args[0])
}

func (a *app) rawGraphQL(args []string) error {
	fs := a.flagset("raw graphql")
	op := fs.String("op", "", "operation name (required)")
	query := fs.String("query", "", "GraphQL document")
	queryFile := fs.String("query-file", "", "read the GraphQL document from a file")
	vars := fs.String("vars", "", "variables as a JSON object")
	if _, err := a.parse("raw graphql", fs, args, 0, 0); err != nil {
		return err
	}
	if *op == "" || (*query == "") == (*queryFile == "") {
		return usagef("raw graphql: --op and exactly one of --query or --query-file are required")
	}
	q := *query
	if *queryFile != "" {
		b, err := os.ReadFile(*queryFile)
		if err != nil {
			return err
		}
		q = string(b)
	}
	var variables map[string]any
	if *vars != "" {
		if err := json.Unmarshal([]byte(*vars), &variables); err != nil {
			return usagef("raw graphql: --vars is not a JSON object: %v", err)
		}
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	var out json.RawMessage
	if err := c.GraphQL(a.ctx, *op, q, variables, &out); err != nil {
		a.printErrBody(err)
		return err
	}
	return a.printRaw(out)
}

func (a *app) rawREST(args []string) error {
	fs := a.flagset("raw rest")
	body := fs.String("body", "", "request body as JSON")
	pos, err := a.parse("raw rest", fs, args, 2, 2)
	if err != nil {
		return err
	}
	method := strings.ToUpper(pos[0])
	u, err := url.Parse(pos[1])
	if err != nil || !strings.HasPrefix(u.Path, "/") {
		return usagef("raw rest: PATH must start with / (got %q)", pos[1])
	}
	var reqBody any
	if *body != "" {
		if !json.Valid([]byte(*body)) {
			return usagef("raw rest: --body is not valid JSON")
		}
		reqBody = json.RawMessage(*body)
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	var out json.RawMessage
	if err := c.REST(a.ctx, method, u.Path, u.Query(), reqBody, &out); err != nil {
		a.printErrBody(err)
		return err
	}
	if len(out) == 0 {
		if !a.json {
			_, _ = fmt.Fprintln(a.stdout, "(no content)")
		}
		return nil
	}
	return a.printRaw(out)
}

// printRaw pretty-prints a JSON document.
func (a *app) printRaw(raw json.RawMessage) error {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		buf.Reset()
		buf.Write(raw)
	}
	buf.WriteByte('\n')
	_, err := a.stdout.Write(buf.Bytes())
	return err
}

// printErrBody shows the server's raw error body for raw requests, which are
// meant for exploration.
func (a *app) printErrBody(err error) {
	var e *butterflymx.Error
	if errors.As(err, &e) && len(e.Body) > 0 {
		_, _ = fmt.Fprintf(a.stderr, "response body: %s\n", truncate(string(e.Body), 1000))
	}
}
