package butterflymxtest

import (
	"encoding/json/v2"
	"net/http"
	"regexp"
	"slices"
	"strings"
)

// hUnlock implements the unlock service. Malformed or missing identifiers get
// 400, a tenant that is not the caller's gets 403 and an unknown access point
// gets 404 (the error bodies are unverified).
func (s *Server) hUnlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccessPointID string `json:"accessPointId"`
		TenantID      string `json:"tenantId"`
		Source        string `json:"source"`
	}
	fail := func(status int, code, msg string) {
		writeJSON(w, status, "application/json; charset=utf-8", map[string]any{"error": code, "message": msg})
	}
	if err := json.UnmarshalRead(r.Body, &req); err != nil {
		fail(http.StatusBadRequest, "bad_request", "malformed JSON body")
		return
	}
	apType, apNum, ok1 := parseGlobalID(req.AccessPointID)
	tType, tNum, ok2 := parseGlobalID(req.TenantID)
	if !ok1 || !ok2 || apType != "access_point" || tType != "tenant" {
		fail(http.StatusBadRequest, "invalid_id", "accessPointId and tenantId must be global IDs")
		return
	}
	if !s.tenantOK(tNum) {
		fail(http.StatusForbidden, "forbidden", "tenant is not accessible")
		return
	}
	a := s.w.ap(apNum)
	if a == nil {
		fail(http.StatusNotFound, "not_found", "access point not found")
		return
	}
	id := s.uuid()
	s.w.unlocks = append(s.w.unlocks, Unlock{
		RequestID: id, AccessPointID: req.AccessPointID, TenantID: req.TenantID, Source: req.Source, At: s.now(),
	})
	s.newRelease(s.now(), a, "SWIPE_TO_OPEN", "", "VISITOR", "visitor", "", "")
	writeCached(w, r, "application/json; charset=utf-8", map[string]any{"requestId": id})
}

var reLocale = regexp.MustCompile(`^[a-z]{2}(-[A-Z]{2})?$`)

// hPushDevice implements POST and PATCH /mobile/v4/users/devices.
func (s *Server) hPushDevice(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSONAPIErrors(w, http.StatusBadRequest, apiErr{Title: "Bad Request", Detail: "malformed form body"})
		return
	}
	var d *pushDevice
	if r.Method == http.MethodPatch {
		d = s.w.push[r.PathValue("id")]
		if d == nil {
			writeJSONAPIErrors(w, http.StatusNotFound, apiErr{Title: "Not Found", Detail: "device not found"})
			return
		}
	} else {
		d = &pushDevice{id: s.randID(8, s.w.used)}
		s.w.push[d.id] = d
	}
	set := func(dst *string, key string) {
		if r.PostForm.Has(key) {
			*dst = r.PostForm.Get(key)
		}
	}
	set(&d.token, "device[token]")
	set(&d.voip, "device[voip_token]")
	set(&d.description, "device[description]")
	set(&d.version, "device[client_version]")
	if r.PostForm.Has("device[development]") {
		d.development = r.PostForm.Get("device[development]") == "1" || strings.EqualFold(r.PostForm.Get("device[development]"), "true")
	}
	if ls, ok := r.PostForm["device[locales][]"]; ok {
		d.locales = nil
		for _, l := range ls {
			if reLocale.MatchString(l) && !slices.Contains(d.locales, l) {
				d.locales = append(d.locales, l)
			}
		}
	}
	push := "push"
	if d.voip != "" {
		push = "voip"
	}
	locales := d.locales
	if locales == nil {
		locales = []string{}
	}
	writeDoc(w, r, http.StatusOK, document{Data: resource{
		ID: d.id, Type: "user_device_apples",
		Attributes: map[string]any{
			"token": d.token, "description": d.description, "client_version": d.version, "voip_token": d.voip,
			"locales": locales, "development": d.development, "graphql_id": "prod-user_device_apple-" + d.id,
			"call_notification_push_type": push,
		},
		Relationships: map[string]relData{"user": {Data: ref{ID: s.w.seed.UserID, Type: "users"}}},
	}})
}

func (s *Server) hPushDeviceDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.w.push[id] == nil {
		writeJSONAPIErrors(w, http.StatusNotFound, apiErr{Title: "Not Found", Detail: "device not found"})
		return
	}
	delete(s.w.push, id)
	w.WriteHeader(http.StatusNoContent)
}
