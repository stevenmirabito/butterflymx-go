package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/stevenmirabito/butterflymx-go"
)

// ---- recipients and schedules ----

// parseRecipients accepts "address", or "Name=address", where address is an
// email address or a phone number. Values may be comma-separated.
func parseRecipients(vals []string) ([]butterflymx.Recipient, error) {
	var out []butterflymx.Recipient
	for _, v := range vals {
		for _, item := range strings.Split(v, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			name, addr := "", item
			if n, ad, ok := strings.Cut(item, "="); ok {
				name, addr = strings.TrimSpace(n), strings.TrimSpace(ad)
			}
			var r butterflymx.Recipient
			if strings.Contains(addr, "@") {
				if name == "" {
					name, _, _ = strings.Cut(addr, "@")
				}
				r = butterflymx.EmailRecipient(name, addr)
			} else {
				if name == "" {
					name = addr
				}
				r = butterflymx.SMSRecipient(name, addr)
			}
			if err := r.Validate(); err != nil {
				return nil, usagef("recipient %q: %v", item, err)
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// scheduleFlags are the flags that describe a pass schedule.
type scheduleFlags struct {
	start, end, weekdays, from, until, startDate, endDate *string
}

func (s *scheduleFlags) register(fs interface {
	String(name, value, usage string) *string
}) {
	s.start = fs.String("start", "", "custom pass start (RFC 3339)")
	s.end = fs.String("end", "", "custom pass end (RFC 3339)")
	s.weekdays = fs.String("weekdays", "", "recurring: comma-separated weekdays, e.g. mon,wed")
	s.from = fs.String("from", "", "recurring: daily window start HH:MM (building time)")
	s.until = fs.String("until", "", "recurring: daily window end HH:MM (building time); in passes create a HH:MM value of --to means the same")
	s.startDate = fs.String("start-date", "", "recurring: first date YYYY-MM-DD")
	s.endDate = fs.String("end-date", "", "recurring: last date YYYY-MM-DD")
}

// schedule returns nil (without error) when no schedule flag was given.
func (s *scheduleFlags) schedule() (butterflymx.Schedule, error) {
	custom := *s.start != "" || *s.end != ""
	recurring := *s.weekdays != "" || *s.from != "" || *s.until != "" || *s.startDate != "" || *s.endDate != ""
	switch {
	case custom && recurring:
		return nil, usagef("use either --start/--end or the recurring flags, not both")
	case custom:
		if *s.start == "" || *s.end == "" {
			return nil, usagef("--start and --end must be given together")
		}
		st, err := time.Parse(time.RFC3339, *s.start)
		if err != nil {
			return nil, usagef("--start: %v", err)
		}
		en, err := time.Parse(time.RFC3339, *s.end)
		if err != nil {
			return nil, usagef("--end: %v", err)
		}
		return butterflymx.CustomSchedule{StartsAt: st, EndsAt: en}, nil
	case recurring:
		if *s.weekdays == "" || *s.from == "" || *s.until == "" || *s.startDate == "" || *s.endDate == "" {
			return nil, usagef("recurring passes need --weekdays, --from, --until, --start-date and --end-date")
		}
		var rs butterflymx.RecurringSchedule
		for _, w := range strings.Split(*s.weekdays, ",") {
			wd, err := butterflymx.ParseWeekday(strings.TrimSpace(strings.ToLower(w)))
			if err != nil {
				return nil, usagef("--weekdays: %v", err)
			}
			rs.Weekdays = append(rs.Weekdays, wd)
		}
		var err error
		if rs.From, err = butterflymx.ParseTimeOfDay(*s.from); err != nil {
			return nil, usagef("--from: %v", err)
		}
		if rs.To, err = butterflymx.ParseTimeOfDay(*s.until); err != nil {
			return nil, usagef("--until/--to: %v", err)
		}
		if rs.StartDate, err = butterflymx.ParseDate(*s.startDate); err != nil {
			return nil, usagef("--start-date: %v", err)
		}
		if rs.EndDate, err = butterflymx.ParseDate(*s.endDate); err != nil {
			return nil, usagef("--end-date: %v", err)
		}
		return rs, nil
	}
	return nil, nil
}

var timeOfDayRe = regexp.MustCompile(`^\d{1,2}:\d{2}$`)

// splitTo separates the --to values of passes create: the spec uses --to both
// for recipients and for the end of a recurring window, so a value shaped like
// HH:MM is the window end and everything else is a recipient.
func splitTo(vals []string) (recipients []string, windowEnd string) {
	for _, v := range vals {
		if timeOfDayRe.MatchString(strings.TrimSpace(v)) {
			windowEnd = strings.TrimSpace(v)
		} else {
			recipients = append(recipients, v)
		}
	}
	return
}

// ---- output ----

func describeSchedule(k butterflymx.Keychain) string {
	switch s := k.Schedule().(type) {
	case butterflymx.CustomSchedule:
		return fmtTime(s.StartsAt) + " -> " + fmtTime(s.EndsAt)
	case butterflymx.RecurringSchedule:
		var days []string
		for _, d := range s.Weekdays {
			days = append(days, string(d))
		}
		return fmt.Sprintf("%s %s-%s, %s..%s (building time)", strings.Join(days, ","), s.From, s.To, s.StartDate, s.EndDate)
	}
	return "-"
}

// stripSecrets removes PINs and QR/instruction URLs from a pass, for listings.
func stripSecrets(k butterflymx.Keychain) butterflymx.Keychain {
	keys := make([]butterflymx.VirtualKey, len(k.VirtualKeys))
	for i, v := range k.VirtualKeys {
		v.PIN, v.QRCodeURL, v.InstructionsURL = "", "", ""
		keys[i] = v
	}
	k.VirtualKeys = keys
	return k
}

func (a *app) printKeys(keys []butterflymx.VirtualKey) {
	for _, v := range keys {
		_, _ = fmt.Fprintf(a.stdout, "  key %s  %s\n", v.ID, v.Name)
		switch {
		case v.Email != "":
			_, _ = fmt.Fprintf(a.stdout, "    sent to: %s\n", v.Email)
		case v.SMSNumber != "":
			_, _ = fmt.Fprintf(a.stdout, "    sent to: %s\n", v.SMSNumber)
		}
		_, _ = fmt.Fprintf(a.stdout, "    PIN:          %s\n", v.PIN.Reveal())
		_, _ = fmt.Fprintf(a.stdout, "    QR:           %s\n", orDash(v.QRCodeURL))
		_, _ = fmt.Fprintf(a.stdout, "    instructions: %s\n", orDash(v.InstructionsURL))
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (a *app) printKeychain(k *butterflymx.Keychain, withKeys bool) {
	_, _ = fmt.Fprintf(a.stdout, "Pass %s  %q  (%s)\n", k.ID, k.Name, k.Kind)
	_, _ = fmt.Fprintf(a.stdout, "  schedule: %s\n", describeSchedule(*k))
	if len(k.Devices) > 0 {
		var ds []string
		for _, d := range k.Devices {
			ds = append(ds, d.Name)
		}
		_, _ = fmt.Fprintf(a.stdout, "  devices:  %s\n", strings.Join(ds, ", "))
	}
	if withKeys {
		a.printKeys(k.VirtualKeys)
	}
}

// emitKeychain prints a pass; PINs and URLs only when showKeys is set.
func (a *app) emitKeychain(k *butterflymx.Keychain, showKeys bool) error {
	if !showKeys {
		k = stripKeys(k)
	}
	if a.json {
		return a.emitJSON(k)
	}
	a.printKeychain(k, showKeys)
	return nil
}

// ---- passes ----

func (a *app) cmdPasses(args []string) error {
	if len(args) == 0 {
		return usagef("passes: expected list, get, create or delete")
	}
	switch args[0] {
	case "list":
		return a.passesList(args[1:])
	case "get":
		return a.passesGet(args[1:])
	case "create":
		return a.passesCreate(args[1:])
	case "delete":
		return a.passesDelete(args[1:])
	}
	return usagef("passes: unknown subcommand %q", args[0])
}

func parseID(what, s string) (butterflymx.ID, error) {
	id, err := butterflymx.ParseID(s)
	if err != nil || id <= 0 {
		return 0, usagef("invalid %s ID %q", what, s)
	}
	return id, nil
}

func (a *app) passesList(args []string) error {
	fs := a.flagset("passes list")
	status := fs.String("status", "active", "active or expired")
	kinds := fs.String("kind", "", "comma-separated kinds: custom,recurring,delivery_pass")
	tenant := fs.String("tenant", "", "tenant ID")
	if _, err := a.parse("passes list", fs, args, 0, 0); err != nil {
		return err
	}
	if *status != "active" && *status != "expired" {
		return usagef("passes list: --status must be active or expired")
	}
	f := butterflymx.KeychainFilter{Status: butterflymx.KeychainStatus(*status)}
	for _, k := range strings.Split(*kinds, ",") {
		switch k = strings.TrimSpace(k); k {
		case "":
		case "custom", "recurring", "delivery_pass":
			f.Kinds = append(f.Kinds, butterflymx.KeychainKind(k))
		default:
			return usagef("passes list: unknown kind %q", k)
		}
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	t, err := a.pickTenant(c, *tenant)
	if err != nil {
		return err
	}
	ks, err := c.Keychains(a.ctx, t.ID, f)
	if err != nil {
		return err
	}
	for i := range ks {
		ks[i] = stripSecrets(ks[i])
	}
	if a.json {
		if ks == nil {
			ks = []butterflymx.Keychain{}
		}
		return a.emitJSON(ks)
	}
	if len(ks) == 0 {
		_, _ = fmt.Fprintln(a.stdout, "No passes.")
		return nil
	}
	rows := make([][]string, len(ks))
	for i, k := range ks {
		rows[i] = []string{k.ID.String(), string(k.Kind), k.Name, describeSchedule(k), fmt.Sprint(len(k.VirtualKeys))}
	}
	a.table([]string{"ID", "KIND", "NAME", "SCHEDULE", "KEYS"}, rows)
	return nil
}

func (a *app) passesGet(args []string) error {
	fs := a.flagset("passes get")
	pos, err := a.parse("passes get", fs, args, 1, 1)
	if err != nil {
		return err
	}
	id, err := parseID("pass", pos[0])
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	k, err := c.Keychain(a.ctx, id)
	if err != nil {
		return err
	}
	if a.json {
		return a.emitJSON(k)
	}
	a.printKeychain(k, true)
	for _, v := range k.VirtualKeys {
		if len(v.Releases) > 0 {
			_, _ = fmt.Fprintf(a.stdout, "  key %s used %d time(s), last %s\n", v.ID, len(v.Releases), fmtTime(v.Releases[0].LoggedAt))
		}
	}
	return nil
}

func (a *app) passesCreate(args []string) error {
	fs := a.flagset("passes create")
	name := fs.String("name", "", "pass name (required)")
	var doors, to listFlag
	fs.Var(&doors, "door", "door ID or name (repeatable, required)")
	fs.Var(&to, "to", "recipient email/phone, optionally Name=address (repeatable, required)")
	tenant := fs.String("tenant", "", "tenant ID")
	var sf scheduleFlags
	sf.register(fs)
	if _, err := a.parse("passes create", fs, args, 0, 0); err != nil {
		return err
	}
	toVals, windowEnd := splitTo(to)
	if *sf.until == "" {
		*sf.until = windowEnd
	}
	sched, err := sf.schedule()
	if err != nil {
		return err
	}
	recips, err := parseRecipients(toVals)
	if err != nil {
		return err
	}
	switch {
	case *name == "":
		return usagef("passes create: --name is required")
	case len(doors) == 0:
		return usagef("passes create: at least one --door is required")
	case sched == nil:
		return usagef("passes create: give a schedule (--start/--end, or the recurring flags)")
	case len(recips) == 0:
		return usagef("passes create: at least one --to is required")
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	t, aps, err := a.tenantAndDoors(c, *tenant)
	if err != nil {
		return err
	}
	chosen, err := resolveDoors(aps, doors)
	if err != nil {
		return err
	}
	k, err := c.CreateKeychain(a.ctx, butterflymx.CreateKeychainParams{
		TenantID: t.ID, AccessPointIDs: doorIDs(chosen), Name: *name, Schedule: sched, Recipients: recips,
	})
	if err != nil {
		return err
	}
	return a.emitKeychain(k, true)
}

func (a *app) passesDelete(args []string) error {
	fs := a.flagset("passes delete")
	pos, err := a.parse("passes delete", fs, args, 1, 1)
	if err != nil {
		return err
	}
	id, err := parseID("pass", pos[0])
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	if err := c.DeleteKeychain(a.ctx, id); err != nil {
		return err
	}
	if a.json {
		return a.emitJSON(map[string]any{"deleted": id})
	}
	_, _ = fmt.Fprintf(a.stdout, "Deleted pass %s\n", id)
	return nil
}

// ---- keys ----

func (a *app) cmdKeys(args []string) error {
	if len(args) == 0 {
		return usagef("keys: expected add or revoke")
	}
	switch args[0] {
	case "add":
		fs := a.flagset("keys add")
		var to listFlag
		fs.Var(&to, "to", "recipient email/phone, optionally Name=address (repeatable, required)")
		pos, err := a.parse("keys add", fs, args[1:], 1, 1)
		if err != nil {
			return err
		}
		id, err := parseID("pass", pos[0])
		if err != nil {
			return err
		}
		recips, err := parseRecipients(to)
		if err != nil {
			return err
		}
		if len(recips) == 0 {
			return usagef("keys add: at least one --to is required")
		}
		c, err := a.client()
		if err != nil {
			return err
		}
		keys, err := c.AddVirtualKeys(a.ctx, id, recips...)
		if err != nil {
			return err
		}
		if a.json {
			return a.emitJSON(keys)
		}
		a.printKeys(keys)
		return nil
	case "revoke":
		fs := a.flagset("keys revoke")
		pos, err := a.parse("keys revoke", fs, args[1:], 2, 2)
		if err != nil {
			return err
		}
		pid, err := parseID("pass", pos[0])
		if err != nil {
			return err
		}
		kid, err := parseID("key", pos[1])
		if err != nil {
			return err
		}
		c, err := a.client()
		if err != nil {
			return err
		}
		if err := c.RevokeVirtualKey(a.ctx, pid, kid); err != nil {
			return err
		}
		if a.json {
			return a.emitJSON(map[string]any{"revoked": kid, "pass": pid})
		}
		_, _ = fmt.Fprintf(a.stdout, "Revoked key %s of pass %s\n", kid, pid)
		return nil
	}
	return usagef("keys: unknown subcommand %q", args[0])
}

// ---- delivery ----

func (a *app) cmdDelivery(args []string) error {
	if len(args) == 0 {
		return usagef("delivery: expected create, rename or extend")
	}
	switch args[0] {
	case "create":
		fs := a.flagset("delivery create")
		name := fs.String("name", "", "pass name (default \"Delivery Pass\")")
		tenant := fs.String("tenant", "", "tenant ID")
		if _, err := a.parse("delivery create", fs, args[1:], 0, 0); err != nil {
			return err
		}
		c, err := a.client()
		if err != nil {
			return err
		}
		t, _, err := a.tenantAndDoors(c, *tenant)
		if err != nil {
			return err
		}
		// Delivery passes always cover every guest-pass door.
		k, err := c.CreateDeliveryPass(a.ctx, butterflymx.DeliveryPassParams{TenantID: t.ID, Name: *name})
		if err != nil {
			return err
		}
		return a.emitKeychain(k, true)
	case "rename":
		fs := a.flagset("delivery rename")
		pos, err := a.parse("delivery rename", fs, args[1:], 2, 2)
		if err != nil {
			return err
		}
		id, err := parseID("pass", pos[0])
		if err != nil {
			return err
		}
		c, err := a.client()
		if err != nil {
			return err
		}
		k, err := c.UpdateDeliveryPass(a.ctx, id, butterflymx.DeliveryPassUpdate{Name: &pos[1]})
		if err != nil {
			return err
		}
		return a.emitKeychain(k, false)
	case "extend":
		fs := a.flagset("delivery extend")
		days := fs.Int("days", 30, "days to add to the end")
		pos, err := a.parse("delivery extend", fs, args[1:], 1, 1)
		if err != nil {
			return err
		}
		id, err := parseID("pass", pos[0])
		if err != nil {
			return err
		}
		c, err := a.client()
		if err != nil {
			return err
		}
		k, err := c.ExtendDeliveryPass(a.ctx, id, time.Duration(*days)*24*time.Hour)
		if err != nil {
			return err
		}
		return a.emitKeychain(k, false)
	}
	return usagef("delivery: unknown subcommand %q", args[0])
}

// stripKeys removes the secrets of a pass that the user did not ask to see.
func stripKeys(k *butterflymx.Keychain) *butterflymx.Keychain {
	s := stripSecrets(*k)
	return &s
}
