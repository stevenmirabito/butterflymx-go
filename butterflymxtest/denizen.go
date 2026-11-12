package butterflymxtest

import (
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// apiAuth wraps a handler so that it only runs with a valid denizen API token.
// The 401 body shape is unverified (spec §8).
func (s *Server) apiAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		t := s.apiTokens[tok]
		desc := ""
		switch {
		case tok == "":
			desc = "Missing bearer token."
		case t == nil:
			desc = "The access token is invalid."
		case t.revoked:
			desc = "The access token was revoked."
		case !t.expires.IsZero() && !s.now().Before(t.expires):
			desc = "The access token expired."
		}
		if desc != "" {
			if strings.HasPrefix(r.URL.Path, "/v3/") || strings.HasPrefix(r.URL.Path, "/mobile/") {
				w.Header().Set("WWW-Authenticate", `Bearer realm="ButterflyMX", error="invalid_token"`)
				writeJSONAPIErrors(w, http.StatusUnauthorized, apiErr{Title: "Unauthorized", Detail: desc})
				return
			}
			unauthorized(w, desc)
			return
		}
		h(w, r)
	}
}

func (s *Server) hDenizenLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccessToken string `json:"access_token"`
		Device      struct {
			Platform string   `json:"platform"`
			Version  string   `json:"version"`
			Locales  []string `json:"locales"`
		} `json:"device"`
	}
	if err := json.UnmarshalRead(r.Body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, "application/json; charset=utf-8", map[string]any{"error": "bad_request"})
		return
	}
	if ok, _ := s.oauthValid(req.AccessToken); !ok {
		unauthorized(w, "The access token is invalid.")
		return
	}
	tok := s.mintAPIToken()
	writeCached(w, r, "application/json; charset=utf-8", map[string]any{"token": tok})
}

// mintAPIToken creates a denizen API token. The caller holds s.mu.
func (s *Server) mintAPIToken() string {
	tok := randToken(256) // 342 base64url chars, no dots
	t := &apiToken{}
	if s.cfg.apiTTL > 0 {
		t.expires = s.now().Add(s.cfg.apiTTL)
	}
	s.apiTokens[tok] = t
	return tok
}

func (s *Server) hDenizenLogout(w http.ResponseWriter, r *http.Request) {
	if t := s.apiTokens[bearer(r)]; t != nil {
		t.revoked = true
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
}

// ---- GraphQL ----------------------------------------------------------------

var reOpName = regexp.MustCompile(`(?:query|mutation)\s+([A-Za-z_]\w*)`)

type gqlRequest struct {
	OperationName string         `json:"operationName"`
	Query         string         `json:"query"`
	Variables     map[string]any `json:"variables"`
}

func gqlError(w http.ResponseWriter, msg, code string) {
	writeJSON(w, http.StatusOK, "application/json; charset=utf-8", map[string]any{
		"data":   nil,
		"errors": []any{map[string]any{"message": msg, "extensions": map[string]any{"code": code}}},
	})
}

func (s *Server) hGraphQL(w http.ResponseWriter, r *http.Request) {
	var req gqlRequest
	if err := json.UnmarshalRead(r.Body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, "application/json; charset=utf-8",
			map[string]any{"errors": []any{map[string]any{"message": "invalid JSON body"}}})
		return
	}
	op := req.OperationName
	if op == "" {
		if m := reOpName.FindStringSubmatch(req.Query); m != nil {
			op = m[1]
		}
	}
	v := req.Variables
	if v == nil {
		v = map[string]any{}
	}
	var data map[string]any
	var err error
	switch op {
	case "CurrentUser":
		data = map[string]any{"currentUser": s.gqlUser()}
	case "Tenants":
		var conn map[string]any
		conn, err = s.offsetConnection("TenantConnection", 1, strVar(v, "after"), func(lo, hi int) []any {
			if hi <= lo {
				return []any{}
			}
			return []any{s.gqlTenant()}
		})
		data = map[string]any{"tenants": conn}
	case "Tenant":
		data = map[string]any{"nodes": s.tenantNodes(idsVar(v, "tenantId"), func(n map[string]any) {
			for k, x := range s.gqlTenant() {
				n[k] = x
			}
		})}
	case "TenantAccessPoints":
		after := strVar(v, "after")
		data = map[string]any{"nodes": s.tenantNodes(idsVar(v, "ids"), func(n map[string]any) {
			var conn map[string]any
			conn, err = s.offsetConnection("AccessPointConnection", len(s.w.aps), after, func(lo, hi int) []any {
				out := []any{}
				for _, a := range s.w.aps[lo:hi] {
					out = append(out, s.gqlAccessPoint(a))
				}
				return out
			})
			n["accessPoints"] = conn
		})}
	case "TenantDoorReleases":
		after := strVar(v, "after")
		data = map[string]any{"nodes": s.tenantNodes(idsVar(v, "tenantIds"), func(n map[string]any) {
			var conn map[string]any
			conn, err = s.doorReleaseConnection(after)
			n["doorReleases"] = conn
		})}
	case "TenantCalls":
		after := strVar(v, "after")
		data = map[string]any{"nodes": s.tenantNodes(idsVar(v, "tenantIds"), func(n map[string]any) {
			calls := slices.Clone(s.w.calls)
			sort.SliceStable(calls, func(i, j int) bool { return calls[i].at.After(calls[j].at) })
			var conn map[string]any
			conn, err = s.offsetConnection("CallConnection", len(calls), after, func(lo, hi int) []any {
				out := []any{}
				for _, c := range calls[lo:hi] {
					out = append(out, s.gqlCall(c))
				}
				return out
			})
			n["calls"] = conn
		})}
	case "TenantMessages":
		after := strVar(v, "after")
		data = map[string]any{"nodes": s.tenantNodes(idsVar(v, "tenantIds"), func(n map[string]any) {
			msgs := slices.Clone(s.w.messages)
			sort.SliceStable(msgs, func(i, j int) bool { return msgs[i].at.After(msgs[j].at) })
			var conn map[string]any
			conn, err = s.offsetConnection("MessageUnionConnection", len(msgs), after, func(lo, hi int) []any {
				out := []any{}
				for _, m := range msgs[lo:hi] {
					out = append(out, map[string]any{
						"__typename": "TextMessage", "id": "prod-text_message-" + m.num, "title": m.title, "body": m.body,
						"createdAt": fmtInstant(m.at), "logoUrl": m.logoURL, "imageUrl": m.imageURL, "origin": "PROPERTY_MANAGER",
						"source": map[string]any{"__typename": "Device", "name": "Main Entrance"},
					})
				}
				return out
			})
			n["messages"] = conn
		})}
	case "TenantLPRSettings":
		data = map[string]any{"nodes": s.tenantNodes(idsVar(v, "ids"), func(n map[string]any) {
			n["vehicleAccessToolLimit"] = nil
			n["vehicleAccessToolsEnabled"] = false
			n["vehicleVisitorPassesEnabled"] = false
		})}
	case "TenantRemoteLocks":
		data = map[string]any{"nodes": s.tenantNodes(idsVar(v, "ids"), func(n map[string]any) {
			n["remoteLocks"] = emptyConnection("RemoteLockConnection")
		})}
	case "TenantSmartLocks":
		data = map[string]any{"nodes": s.tenantNodes(idsVar(v, "ids"), func(n map[string]any) {
			n["smartLocks"] = emptyConnection("SmartLockConnection")
		})}
	case "GetBLECredentials":
		ids := idsVar(v, "tenantId")
		nodes := []any{}
		for _, id := range ids {
			if id != s.w.seed.TenantGlobalID {
				nodes = append(nodes, nil)
				continue
			}
			nodes = append(nodes, map[string]any{
				"__typename": "Tenant",
				"building": map[string]any{
					"__typename":           "Building",
					"intercomBleDeviceKey": "f1cd8b9066370a049888dc1e2f9a573a",
					"wavelynxReaderBleCredential": map[string]any{
						"__typename":              "WavelynxReaderCredential",
						"encryptedCredentialBlob": "93d12efce1dff9c63f8b9753a371c345b102a5802067edc099d46e9e3ee8c3af661a6ebb59ca3437efd6d7ae3a51e684fd4b4d7cd1fe74f55ce5559c15e49bfd",
						"kmd":                     "5e6493ae83802f6c0bf92140c3d59194",
					},
				},
			})
		}
		data = map[string]any{"nodes": nodes}
	default:
		gqlError(w, fmt.Sprintf("Unknown operation %q", op), "UNKNOWN_OPERATION")
		return
	}
	if err != nil {
		gqlError(w, err.Error(), "BAD_USER_INPUT")
		return
	}
	writeJSON(w, http.StatusOK, "application/json; charset=utf-8", map[string]any{"data": data})
}

func strVar(v map[string]any, k string) string {
	s, _ := v[k].(string)
	return s
}

// idsVar reads a variable that is either one ID or a list of IDs.
func idsVar(v map[string]any, k string) []string {
	switch t := v[k].(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// tenantNodes implements nodes(ids:): one entry per id, null for ids that are
// not the seeded tenant. fill adds the per-operation fields to a tenant stub.
func (s *Server) tenantNodes(ids []string, fill func(map[string]any)) []any {
	out := []any{}
	for _, id := range ids {
		if id != s.w.seed.TenantGlobalID {
			out = append(out, nil)
			continue
		}
		n := map[string]any{"__typename": "Tenant", "id": id}
		if fill != nil {
			fill(n)
		}
		out = append(out, n)
	}
	return out
}

func (s *Server) gqlUser() map[string]any {
	return map[string]any{
		"__typename": "User", "id": s.w.seed.UserGlobalID,
		"firstName": "Resident", "lastName": "Example", "email": DefaultEmail, "phoneNumber": "5555550100",
		"avatarUrl": "https://example.com/avatar.jpg", "hasDormakabaSmartLock": false, "contactPreference": "VIDEO_CALL",
		"twoFactorAuthenticationConfig": map[string]any{
			"__typename": "UserMultiFactorAuthenticationConfig", "enabled": s.cfg.mfa, "required": false,
			"types": []string{"EMAIL", "SMS", "AUTHENTICATOR_APP"},
		},
		"acknowledgedPrivacyPolicyVersion": "2026-01-23",
	}
}

func (s *Server) gqlBuilding() map[string]any {
	sd := s.w.seed
	return map[string]any{
		"__typename": "Building", "id": sd.BuildingGID, "guid": sd.BuildingGUID, "name": sd.BuildingName,
		"address":             map[string]any{"__typename": "Address", "country": "us"},
		"capabilities":        []string{"BLE_ACCESS_ENABLED", "DELIVERY_PASS_ENABLED", "DOOR_PIN_ENABLED", "VIRTUAL_KEYS_ENABLED"},
		"enabledIntegrations": []string{}, "contactLabel": "", "contactPhoneNumber": nil,
		"timeZone": sd.TimeZone, "amenityReservationsFeeStrategy": "RECORD_PAYMENTS",
		"virtualKeysDurationPeriod": sd.VirtualKeysDurationDays, "geofence": nil, "suspended": false,
	}
}

func (s *Server) gqlTenant() map[string]any {
	sd := s.w.seed
	return map[string]any{
		"__typename": "Tenant", "id": sd.TenantGlobalID,
		"firstName": "Resident", "lastName": "Example", "name": "Resident Example",
		"inactiveAfter": nil, "awayMessage": nil, "pinCode": "012345", "legacyPinCode": nil,
		"deliveryPassEnabled": true, "virtualKeyEnabled": true, "privacyConsentGiven": true, "virtualFobEntryEnabled": false,
		"unit":     map[string]any{"__typename": "Unit", "id": sd.UnitGlobalID, "label": sd.UnitLabel, "floorNumber": "4"},
		"building": s.gqlBuilding(),
		"notificationPreference": map[string]any{
			"__typename": "NotificationPreference", "call": "VIDEO_CALL", "doNotDisturb": false,
			"doorOpen": []string{"NOTIFICATION"}, "message": []string{"NOTIFICATION", "SMS"},
		},
		"geofenceEnabled": false, "maintenanceRequestsEnabled": false,
	}
}

func (s *Server) gqlAccessPoint(a *accessPoint) map[string]any {
	days := []string{"MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY", "SUNDAY"}
	dev := map[string]any{"__typename": a.dev.gqlType, "id": a.dev.gid(), "name": a.dev.name}
	if a.dev.gqlType == "Intercom" {
		dev["serialNumber"] = a.dev.serial
	} else {
		dev["readerSerialNumbers"] = a.readerSerials
	}
	return map[string]any{
		"__typename": "AccessPoint", "id": a.gid(), "legacyId": a.id, "name": a.name,
		"capabilities": a.caps, "openDuration": a.openDuration, "online": true, "inOpenHours": false,
		"doorOpenSchedules": []any{},
		"accessTimes":       []any{map[string]any{"__typename": "TimeRestriction", "from": "00:00", "to": "00:00", "days": days}},
		"building":          s.gqlBuilding(),
		"reservations":      map[string]any{"__typename": "ReservationUnionConnection", "nodes": []any{}},
		"devices":           map[string]any{"__typename": "DeviceUnionConnection", "nodes": []any{dev}},
	}
}

func (s *Server) gqlCall(c *callRec) map[string]any {
	d := s.w.deviceByGQL("86254")
	return map[string]any{
		"__typename": "Call", "id": "prod-call-" + c.num, "guid": c.guid, "loggedAt": fmtInstant(c.at),
		"imageUrl": c.imageURL, "notificationType": c.notif, "displayStatus": c.status,
		"device": map[string]any{"__typename": d.gqlType, "id": d.gid(), "name": d.name},
	}
}

func (w *world) deviceByGQL(id string) *device {
	for _, d := range w.devs {
		if d.gqlID == id {
			return d
		}
	}
	return w.devs[0]
}

func emptyConnection(typename string) map[string]any {
	return map[string]any{
		"__typename": typename,
		"pageInfo":   map[string]any{"__typename": "PageInfo", "hasNextPage": false, "endCursor": nil},
		"nodes":      []any{},
	}
}

var errBadCursor = errors.New("invalid cursor")

func encodeOffset(n int) string { return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(n))) }

func decodeOffset(c string) (int, error) {
	if c == "" {
		return 0, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(c, "="))
	if err != nil {
		return 0, errBadCursor
	}
	n, err := strconv.Atoi(string(b))
	if err != nil || n < 0 {
		return 0, errBadCursor
	}
	return n, nil
}

// offsetConnection builds a Relay connection over total items whose cursors are
// base64 offsets, like most ButterflyMX connections.
func (s *Server) offsetConnection(typename string, total int, after string, nodes func(lo, hi int) []any) (map[string]any, error) {
	lo, err := decodeOffset(after)
	if err != nil {
		return nil, err
	}
	lo = min(lo, total)
	hi := min(lo+s.cfg.pageSize, total)
	var end any
	if hi > lo {
		end = encodeOffset(hi)
	}
	return map[string]any{
		"__typename": typename,
		"pageInfo":   map[string]any{"__typename": "PageInfo", "hasNextPage": hi < total, "endCursor": end},
		"nodes":      nodes(lo, hi),
	}, nil
}

func releaseCursor(r *doorRelease) string {
	j := fmt.Sprintf(`{"occurredAt":%q,"id":%q}`, r.at.UTC().Format("2006-01-02T15:04:05.000Z"), r.cursorID)
	return base64.StdEncoding.EncodeToString([]byte(j))
}

func (s *Server) doorReleaseConnection(after string) (map[string]any, error) {
	rs := slices.Clone(s.w.releases)
	sort.SliceStable(rs, func(i, j int) bool {
		if !rs[i].at.Equal(rs[j].at) {
			return rs[i].at.After(rs[j].at)
		}
		return rs[i].gqlNum > rs[j].gqlNum
	})
	lo := 0
	if after != "" {
		b, err := base64.StdEncoding.DecodeString(after)
		if err != nil {
			return nil, errBadCursor
		}
		var c struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(b, &c) != nil {
			return nil, errBadCursor
		}
		idx := slices.IndexFunc(rs, func(r *doorRelease) bool { return r.cursorID == c.ID })
		if idx < 0 {
			return nil, errBadCursor
		}
		lo = idx + 1
	}
	hi := min(lo+s.cfg.pageSize, len(rs))
	nodes := []any{}
	for _, r := range rs[lo:hi] {
		a := s.w.ap(r.apID)
		nodes = append(nodes, map[string]any{
			"__typename": "DoorRelease", "id": r.gid(), "loggedAt": fmtInstant(r.at), "imageUrl": r.imageURL,
			"licensePlate": nil, "type": r.gqlType, "method": r.gqlMethod,
			"accessPoint": map[string]any{"__typename": "AccessPoint", "id": a.gid(), "name": a.name},
			"device":      map[string]any{"__typename": a.dev.gqlType, "id": a.dev.gid(), "name": a.dev.name},
		})
	}
	var end any
	if hi > lo {
		end = releaseCursor(rs[hi-1])
	}
	return map[string]any{
		"__typename": "DoorReleaseConnection",
		"pageInfo":   map[string]any{"__typename": "PageInfo", "hasNextPage": hi < len(rs), "endCursor": end},
		"nodes":      nodes,
	}, nil
}
