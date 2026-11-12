package butterflymxtest

import (
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- JSON:API documents -----------------------------------------------------

type ref struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type relData struct {
	Data any `json:"data"`
}

type resource struct {
	ID            string             `json:"id"`
	Type          string             `json:"type"`
	Attributes    map[string]any     `json:"attributes"`
	Relationships map[string]relData `json:"relationships,omitempty"`
}

type document struct {
	Data     any            `json:"data"`
	Included []resource     `json:"included,omitempty"`
	Links    map[string]any `json:"links,omitempty"`
}

type includer struct {
	seen map[string]bool
	out  []resource
}

func (i *includer) add(r resource) {
	k := r.Type + "/" + r.ID
	if i.seen == nil {
		i.seen = map[string]bool{}
	}
	if !i.seen[k] {
		i.seen[k] = true
		i.out = append(i.out, r)
	}
}

func optStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func parseInclude(v string) map[string]bool {
	m := map[string]bool{}
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			m[p] = true
		}
	}
	return m
}

func (inc includeSet) has(prefix string) bool {
	for k := range inc {
		if k == prefix || strings.HasPrefix(k, prefix+".") {
			return true
		}
	}
	return false
}

type includeSet map[string]bool

func (s *Server) deviceRef(d *device) ref { return ref{ID: d.restID, Type: d.restType} }

func (s *Server) deviceResource(d *device) resource {
	attrs := map[string]any{"name": d.name}
	if d.restType == "panels" {
		attrs["nfc"] = map[string]any{"uuid": ""}
	}
	return resource{ID: d.restID, Type: d.restType, Attributes: attrs, Relationships: map[string]relData{
		"building": {Data: ref{ID: s.w.seed.BuildingID, Type: "buildings"}},
	}}
}

func (s *Server) releasesOf(vkID string) []*doorRelease {
	var out []*doorRelease
	for _, r := range s.w.releases {
		if r.vkID == vkID {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].at.After(out[j].at) })
	return out
}

func (s *Server) releaseResource(r *doorRelease) resource {
	a := s.w.ap(r.apID)
	var panel any
	if a.dev.restType == "panels" {
		panel = s.deviceRef(a.dev)
	}
	return resource{ID: r.restID, Type: "door_releases", Attributes: map[string]any{
		"release_method": r.restMeth, "door_release_type": r.restType, "panel_user_type": "default",
		"call_guid": nil, "delivery_guid": nil, "name": r.name,
		"created_at": fmtInstant(r.at), "logged_at": fmtInstant(r.at),
		"thumb_url": r.imageURL, "medium_url": r.imageURL,
	}, Relationships: map[string]relData{
		"unit":   {Data: ref{ID: s.w.seed.UnitID, Type: "units"}},
		"user":   {Data: ref{ID: s.w.seed.UserID, Type: "users"}},
		"panel":  {Data: panel},
		"device": {Data: s.deviceRef(a.dev)},
	}}
}

func (s *Server) vkResource(v *virtualKey) resource {
	rels := []ref{}
	for _, r := range s.releasesOf(v.id) {
		rels = append(rels, ref{ID: r.restID, Type: "door_releases"})
	}
	return resource{ID: v.id, Type: "virtual_keys", Attributes: map[string]any{
		"name": v.name, "qr_code_image_url": v.qrURL, "email": optStr(v.email), "sms_number": optStr(v.sms),
		"used_at": fmtOptInstant(v.usedAt), "one_time_key_used_at": fmtOptInstant(v.usedAt),
		"pin": v.pin, "instructions_url": v.instrURL, "sent_at": fmtOptInstant(v.sentAt),
		"synced_with_remote_lock": false,
	}, Relationships: map[string]relData{
		"door_releases": {Data: rels},
		"vehicle":       {Data: nil},
	}}
}

func (s *Server) keychainResource(k *keychain) resource {
	vks := []ref{}
	for _, v := range k.vks {
		vks = append(vks, ref{ID: v.id, Type: "virtual_keys"})
	}
	devs := []ref{}
	for _, d := range s.w.devices(k) {
		devs = append(devs, s.deviceRef(d))
	}
	wd := k.weekdays
	if wd == nil {
		wd = []string{}
	}
	return resource{ID: k.id, Type: "keychains", Attributes: map[string]any{
		"name": k.name, "weekdays": wd, "starts_at": fmtInstant(k.startsAt), "ends_at": fmtInstant(k.endsAt),
		"time_from": k.timeFrom, "time_to": k.timeTo, "kind": k.kind,
		"start_date": k.startDate, "end_date": k.endDate, "allow_unit_access": k.allowUnit,
	}, Relationships: map[string]relData{
		"virtual_keys": {Data: vks},
		"devices":      {Data: devs},
	}}
}

// includeFor adds the resources of k requested by inc to out.
func (s *Server) includeFor(k *keychain, inc includeSet, out *includer) {
	if inc.has("virtual_keys") {
		for _, v := range k.vks {
			out.add(s.vkResource(v))
		}
	}
	if inc["virtual_keys.door_releases"] || inc["virtual_keys.door_releases.panel"] {
		for _, v := range k.vks {
			for _, r := range s.releasesOf(v.id) {
				out.add(s.releaseResource(r))
			}
		}
	}
	if inc["devices"] {
		for _, d := range s.w.devices(k) {
			out.add(s.deviceResource(d))
		}
	}
	if inc["virtual_keys.door_releases.panel"] {
		for _, v := range k.vks {
			for _, r := range s.releasesOf(v.id) {
				if d := s.w.ap(r.apID).dev; d.restType == "panels" {
					out.add(s.deviceResource(d))
				}
			}
		}
	}
}

func writeDoc(w http.ResponseWriter, r *http.Request, status int, doc document) {
	b, err := json.Marshal(doc, json.Deterministic(true))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tag := weakETag(b)
	w.Header().Set("ETag", tag)
	if r.Method == http.MethodGet && etagMatches(r.Header.Get("If-None-Match"), tag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", jsonAPIType)
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// ---- reads ------------------------------------------------------------------

func (s *Server) tenantOK(id string) bool { return id == s.w.seed.TenantID }

func (s *Server) hAccessCodes(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.flushDeliveries()
	now := s.now()

	if t := q.Get("filter[tenant]"); t != "" && !s.tenantOK(t) {
		writeJSONAPIErrors(w, http.StatusForbidden, apiErr{Title: "Forbidden", Detail: "tenant not accessible", Pointer: "filter[tenant]"})
		return
	}
	// Only "active" and "expired" filter. Like the real server, any other
	// value is ignored and every pass is returned: "upcoming", "all" and "inactive" all gave active ∪ expired.
	status := q.Get("filter[status]")
	size, number := s.cfg.pageSize, 1
	if v := q.Get("page[size]"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeValidation(w, apiErr{Title: "Invalid page", Detail: "page[size] must be a positive integer", Pointer: "page[size]"})
			return
		}
		size = min(n, 100)
	}
	if v := q.Get("page[number]"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeValidation(w, apiErr{Title: "Invalid page", Detail: "page[number] must be a positive integer", Pointer: "page[number]"})
			return
		}
		number = n
	}

	var list []*keychain
	for _, k := range s.w.keychains {
		if k.tenantID != s.w.seed.TenantID {
			continue
		}
		switch status {
		case "active":
			if k.expired(now) {
				continue
			}
		case "expired":
			if !k.expired(now) {
				continue
			}
		}
		list = append(list, k)
	}
	// Newest end first, for both lists.
	sort.SliceStable(list, func(i, j int) bool {
		if !list[i].endsAt.Equal(list[j].endsAt) {
			return list[i].endsAt.After(list[j].endsAt)
		}
		return list[i].id > list[j].id
	})
	pages := max(1, (len(list)+size-1)/size)
	lo := min((number-1)*size, len(list))
	hi := min(lo+size, len(list))

	inc := includeSet(parseInclude(q.Get("include")))
	var inclr includer
	data := []resource{}
	for _, k := range list[lo:hi] {
		data = append(data, s.keychainResource(k))
		s.includeFor(k, inc, &inclr)
	}

	link := func(n int) any {
		v := url.Values{}
		for k, vs := range q {
			v[k] = vs
		}
		v.Set("page[number]", strconv.Itoa(n))
		v.Set("page[size]", strconv.Itoa(size))
		return s.baseURL(r) + r.URL.Path + "?" + v.Encode()
	}
	links := map[string]any{"self": link(number), "first": link(1), "last": link(pages), "prev": nil, "next": nil}
	if number > 1 {
		links["prev"] = link(min(number-1, pages))
	}
	if number < pages {
		links["next"] = link(number + 1)
	}
	writeDoc(w, r, http.StatusOK, document{Data: data, Included: inclr.out, Links: links})
}

func (s *Server) hGetKeychain(w http.ResponseWriter, r *http.Request) {
	s.flushDeliveries()
	k := s.w.keychain(r.PathValue("id"))
	if k == nil {
		writeJSONAPIErrors(w, http.StatusNotFound, apiErr{Title: "Not Found", Detail: "keychain not found"})
		return
	}
	var inclr includer
	s.includeFor(k, includeSet(parseInclude(r.URL.Query().Get("include"))), &inclr)
	writeDoc(w, r, http.StatusOK, document{Data: s.keychainResource(k), Included: inclr.out})
}

// ---- writes -----------------------------------------------------------------

type ident struct {
	Type string  `json:"type"`
	ID   *string `json:"id"`
}

type kcAttrs struct {
	Name            *string     `json:"name"`
	Kind            *string     `json:"kind"`
	StartsAt        *string     `json:"starts_at"`
	EndsAt          *string     `json:"ends_at"`
	StartDate       *string     `json:"start_date"`
	EndDate         *string     `json:"end_date"`
	TimeFrom        *string     `json:"time_from"`
	TimeTo          *string     `json:"time_to"`
	Weekdays        []string    `json:"weekdays"`
	AllowUnitAccess *bool       `json:"allow_unit_access"`
	Recipients      []recipient `json:"recipients"`
}

type kcRequest struct {
	Data struct {
		Type          string  `json:"type"`
		Attributes    kcAttrs `json:"attributes"`
		Relationships struct {
			Tenant struct {
				Data *ident `json:"data"`
			} `json:"tenant"`
			AccessPoints struct {
				Data []ident `json:"data"`
			} `json:"access_points"`
		} `json:"relationships"`
	} `json:"data"`
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.UnmarshalRead(r.Body, v); err != nil {
		writeJSONAPIErrors(w, http.StatusBadRequest, apiErr{Title: "Bad Request", Detail: "malformed JSON:API document: " + err.Error()})
		return false
	}
	return true
}

var allWeekdays = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}

const attrPtr = "/data/attributes/"

// checkAPs validates access point ids; it returns the ids.
func (s *Server) checkAPs(idents []ident) (ids []string, errs []apiErr) {
	for i, id := range idents {
		ptr := fmt.Sprintf("/data/relationships/access_points/data/%d", i)
		if id.ID == nil {
			errs = append(errs, apiErr{Title: "Invalid access point", Detail: "id can't be blank", Pointer: ptr, Code: "blank"})
			continue
		}
		a := s.w.ap(*id.ID)
		switch {
		case a == nil:
			errs = append(errs, apiErr{Title: "Invalid access point", Detail: fmt.Sprintf("access point %s was not found", *id.ID), Pointer: ptr, Code: "not_found"})
		case !a.hasCap("VIRTUAL_KEYS"):
			errs = append(errs, apiErr{Title: "Invalid access point", Detail: fmt.Sprintf("access point %s (%s) does not support virtual keys", a.id, a.name), Pointer: ptr, Code: "unsupported"})
		case !slices.Contains(ids, a.id):
			ids = append(ids, a.id)
		}
	}
	return ids, errs
}

func checkRecipients(rs []recipient) []apiErr {
	var errs []apiErr
	for i, r := range rs {
		if _, _, err := classifyDeliverTo(r.DeliverTo); err != nil {
			errs = append(errs, apiErr{
				Title: "Invalid recipient", Detail: "deliver_to " + err.Error(),
				Pointer: fmt.Sprintf("%srecipients/%d/deliver_to", attrPtr, i), Code: "invalid",
			})
		}
	}
	return errs
}

// Validation errors. Only the end-before-start and >365-day messages are the
// real ones. The messages of every other validation failure the fake invents
// (door without VIRTUAL_KEYS, unknown tenant, bad recipient, blank fields,
// ...) are unverified; they use the same 400 shape (source.pointer + detail
// only).
func blankErr(attr string) apiErr {
	return apiErr{Title: "Invalid attribute", Detail: attr + " can't be blank", Pointer: attrPtr + attr, Code: "blank"}
}

func invalidErr(attr, detail string) apiErr {
	return apiErr{Title: "Invalid attribute", Detail: attr + " " + detail, Pointer: attrPtr + attr, Code: "invalid"}
}

// applySchedule sets the schedule of k from a. On create every field the kind
// needs is required; on patch absent (or null) fields keep their value.
func (s *Server) applySchedule(k *keychain, a *kcAttrs, create bool) []apiErr {
	var errs []apiErr
	maxDur := time.Duration(s.w.maxVK) * 24 * time.Hour
	tooLong := apiErr{
		Pointer: attrPtr + "ends_at", // real message
		Detail:  fmt.Sprintf("cannot exceed %d days from start date", s.w.maxVK),
	}
	switch k.kind {
	case "custom", "delivery_pass":
		starts, ends := k.startsAt, k.endsAt
		if a.StartsAt != nil && k.kind == "custom" {
			t, err := parseInstant(*a.StartsAt)
			if err != nil {
				errs = append(errs, invalidErr("starts_at", "is not a valid RFC 3339 timestamp"))
			} else {
				starts = t
			}
		} else if create && k.kind == "custom" {
			errs = append(errs, blankErr("starts_at"))
		}
		switch {
		case a.EndsAt != nil: // ends_at wins over end_date
			t, err := parseInstant(*a.EndsAt)
			if err != nil {
				errs = append(errs, invalidErr("ends_at", "is not a valid RFC 3339 timestamp"))
			} else {
				ends = t
			}
		case a.EndDate != nil && !create && *a.EndDate != k.endDate:
			t, err := time.ParseInLocation(dateLayout+" "+clockLayout, *a.EndDate+" "+k.timeTo, s.w.loc)
			if err != nil {
				errs = append(errs, invalidErr("end_date", "is not a valid date"))
			} else {
				ends = t.UTC()
			}
		case create && k.kind == "custom":
			errs = append(errs, blankErr("ends_at"))
		}
		if len(errs) > 0 {
			return errs
		}
		if !ends.After(starts) {
			// The real messages.
			return []apiErr{
				{Pointer: attrPtr + "starts_at", Detail: "Start time must be before the end time"},
				{Pointer: attrPtr + "ends_at", Detail: "End time must be after the start time"},
			}
		}
		if ends.Sub(starts) > maxDur {
			return []apiErr{tooLong}
		}
		k.startsAt, k.endsAt = starts, ends
		k.fromInstants(s.w.loc)
	case "recurring":
		sd, ed, tf, tt := k.startDate, k.endDate, k.timeFrom, k.timeTo
		wd := k.weekdays
		set := func(dst *string, v *string, name, layout string) {
			if v == nil {
				if create {
					errs = append(errs, blankErr(name))
				}
				return
			}
			if _, err := time.Parse(layout, *v); err != nil {
				errs = append(errs, invalidErr(name, "is not a valid "+map[string]string{dateLayout: "date (YYYY-MM-DD)", clockLayout: "time (HH:MM)"}[layout]))
				return
			}
			*dst = *v
		}
		set(&sd, a.StartDate, "start_date", dateLayout)
		set(&ed, a.EndDate, "end_date", dateLayout)
		set(&tf, a.TimeFrom, "time_from", clockLayout)
		set(&tt, a.TimeTo, "time_to", clockLayout)
		if a.Weekdays != nil {
			wd = a.Weekdays
		}
		if len(wd) == 0 {
			errs = append(errs, apiErr{Title: "Invalid attribute", Detail: "weekdays can't be blank", Pointer: attrPtr + "weekdays", Code: "blank"})
		}
		for _, d := range wd {
			if !slices.Contains(allWeekdays, d) {
				errs = append(errs, invalidErr("weekdays", fmt.Sprintf("contains unknown weekday %q", d)))
			}
		}
		if len(errs) > 0 {
			return errs
		}
		start, _ := time.Parse(dateLayout, sd)
		end, _ := time.Parse(dateLayout, ed)
		if end.Before(start) {
			return []apiErr{invalidErr("end_date", "must not be before start_date")}
		}
		if end.Sub(start) > maxDur {
			e := tooLong
			e.Pointer = attrPtr + "end_date"
			return []apiErr{e}
		}
		wdSorted := slices.Clone(wd)
		sort.SliceStable(wdSorted, func(i, j int) bool {
			return slices.Index(allWeekdays, wdSorted[i]) < slices.Index(allWeekdays, wdSorted[j])
		})
		k.startDate, k.endDate, k.timeFrom, k.timeTo = sd, ed, tf, tt
		k.weekdays = slices.Compact(wdSorted)
		if err := k.fromLocal(s.w.loc); err != nil {
			return []apiErr{invalidErr("start_date", err.Error())}
		}
	}
	return nil
}

func (s *Server) hCreateKeychain(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req kcRequest
		if !decodeBody(w, r, &req) {
			return
		}
		a := &req.Data.Attributes
		var errs []apiErr
		if t := req.Data.Relationships.Tenant.Data; t == nil || t.ID == nil {
			errs = append(errs, apiErr{Title: "Invalid relationship", Detail: "tenant can't be blank", Pointer: "/data/relationships/tenant", Code: "blank"})
		} else if !s.tenantOK(*t.ID) {
			errs = append(errs, apiErr{Title: "Invalid relationship", Detail: "tenant was not found", Pointer: "/data/relationships/tenant", Code: "not_found"})
		}
		k := &keychain{id: "", kind: kind, tenantID: s.w.seed.TenantID, allowUnit: false}
		if a.Name != nil {
			k.name = strings.TrimSpace(*a.Name)
		}
		if kind == "delivery_pass" && k.name == "" {
			k.name = "Delivery Pass"
		}
		if k.name == "" {
			errs = append(errs, blankErr("name"))
		}
		var apIDs []string
		if kind != "delivery_pass" {
			var apErrs []apiErr
			apIDs, apErrs = s.checkAPs(req.Data.Relationships.AccessPoints.Data)
			errs = append(errs, apErrs...)
			if len(req.Data.Relationships.AccessPoints.Data) == 0 {
				errs = append(errs, apiErr{Title: "Invalid relationship", Detail: "access_points can't be blank", Pointer: "/data/relationships/access_points", Code: "blank"})
			}
			errs = append(errs, checkRecipients(a.Recipients)...)
		}
		now := s.now()
		if kind == "delivery_pass" {
			// access_points is ignored: a delivery
			// pass always covers every door that supports virtual keys.
			for _, ap := range s.w.aps {
				if ap.hasCap("VIRTUAL_KEYS") {
					apIDs = append(apIDs, ap.id)
				}
			}
			k.startsAt, k.endsAt = now, now.Add(30*24*time.Hour)
			k.fromInstants(s.w.loc)
		} else {
			errs = append(errs, s.applySchedule(k, a, true)...)
		}
		if len(errs) > 0 {
			writeValidation(w, errs...)
			return
		}
		k.apIDs = apIDs
		k.id = s.randID(8, s.w.used)
		s.w.keychains = append(s.w.keychains, k)
		if kind == "delivery_pass" {
			vk := s.newVirtualKey(k.name, "", "")
			k.vks = append(k.vks, vk)
		} else {
			s.addRecipientKeys(k, a.Recipients)
		}
		inc := includeSet{"virtual_keys": true}
		if kind != "delivery_pass" { // the delivery pass fixture has no devices in "included"
			inc["devices"] = true
		}
		var inclr includer
		s.includeFor(k, inc, &inclr)
		writeDoc(w, r, http.StatusCreated, document{Data: s.keychainResource(k), Included: inclr.out})
	}
}

// hPatchKeychain handles PATCH /v3/keychains/{kind}/{id} and answers 204. Only
// the delivery-pass variant exists; guest passes are immutable.
func (s *Server) hPatchKeychain(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		k := s.w.keychain(r.PathValue("id"))
		if k == nil || k.kind != kind {
			writeJSONAPIErrors(w, http.StatusNotFound, apiErr{Title: "Not Found", Detail: "keychain not found"})
			return
		}
		var req kcRequest
		if !decodeBody(w, r, &req) {
			return
		}
		a := &req.Data.Attributes
		work := *k
		work.weekdays = slices.Clone(k.weekdays)
		var errs []apiErr
		if a.Name != nil {
			if n := strings.TrimSpace(*a.Name); n == "" {
				errs = append(errs, blankErr("name"))
			} else {
				work.name = n
			}
		}
		if a.AllowUnitAccess != nil {
			work.allowUnit = *a.AllowUnitAccess
		}
		errs = append(errs, s.applySchedule(&work, a, false)...)
		if len(errs) > 0 {
			writeValidation(w, errs...)
			return
		}
		if kind == "delivery_pass" && work.name != k.name {
			for _, v := range k.vks {
				v.name = work.name
			}
		}
		vks := k.vks
		*k = work
		k.vks = vks
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) hAddVirtualKeys(w http.ResponseWriter, r *http.Request) {
	k := s.w.keychain(r.PathValue("id"))
	if k == nil {
		writeJSONAPIErrors(w, http.StatusNotFound, apiErr{Title: "Not Found", Detail: "keychain not found"})
		return
	}
	var req struct {
		Data struct {
			Attributes struct {
				Recipients []recipient `json:"recipients"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	rs := req.Data.Attributes.Recipients
	var errs []apiErr
	if k.kind == "delivery_pass" {
		errs = append(errs, apiErr{Title: "Invalid keychain", Detail: "delivery passes cannot have recipients", Pointer: attrPtr + "recipients", Code: "invalid"})
	}
	if len(rs) == 0 {
		errs = append(errs, blankErr("recipients"))
	}
	errs = append(errs, checkRecipients(rs)...)
	if len(errs) > 0 {
		writeValidation(w, errs...)
		return
	}
	data := []resource{}
	for _, v := range s.addRecipientKeys(k, rs) {
		data = append(data, s.vkResource(v))
	}
	writeDoc(w, r, http.StatusCreated, document{Data: data})
}

func (s *Server) hDeleteKeychain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	i := slices.IndexFunc(s.w.keychains, func(k *keychain) bool { return k.id == id })
	if i < 0 {
		writeJSONAPIErrors(w, http.StatusNotFound, apiErr{Title: "Not Found", Detail: "keychain not found"})
		return
	}
	s.w.keychains = slices.Delete(s.w.keychains, i, i+1)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) hDeleteVirtualKey(w http.ResponseWriter, r *http.Request) {
	k := s.w.keychain(r.PathValue("id"))
	if k == nil {
		writeJSONAPIErrors(w, http.StatusNotFound, apiErr{Title: "Not Found", Detail: "keychain not found"})
		return
	}
	vk := r.PathValue("vk")
	i := slices.IndexFunc(k.vks, func(v *virtualKey) bool { return v.id == vk })
	if i < 0 {
		writeJSONAPIErrors(w, http.StatusNotFound, apiErr{Title: "Not Found", Detail: "virtual key not found"})
		return
	}
	k.vks = slices.Delete(k.vks, i, i+1)
	w.WriteHeader(http.StatusNoContent)
}
