package butterflymx

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/stevenmirabito/butterflymx-go/internal/jsonapi"
)

// PushDevice is a registered mobile push device (a "user device" in the
// /mobile/v4 API). Registering one is what the official app does at launch so
// that ButterflyMX can send it call notifications; a backend normally has no
// need for it.
//
// Token and VoIPToken are secrets. PushDevice implements [slog.LogValuer] and
// [fmt.Stringer] to keep them out of logs; do not log the fields directly.
type PushDevice struct {
	ID ID
	// GlobalID is the GraphQL ID, for example "prod-user_device_apple-65794426".
	GlobalID GlobalID
	// Client is the platform, for example "iphone".
	Client                   string
	Description              string
	ClientVersion            string
	Locales                  []string
	Development              bool
	CallNotificationPushType string // "voip" or "push"; other values are preserved
	Token, VoIPToken         string // never logged
}

// LogValue implements [slog.LogValuer]. It omits the push tokens.
func (d PushDevice) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", d.ID.String()),
		slog.String("global_id", d.GlobalID.String()),
		slog.String("client", d.Client),
		slog.String("description", d.Description),
		slog.String("client_version", d.ClientVersion),
		slog.Bool("development", d.Development),
		slog.String("call_notification_push_type", d.CallNotificationPushType),
		slog.Bool("has_token", d.Token != ""),
		slog.Bool("has_voip_token", d.VoIPToken != ""),
	)
}

// String implements [fmt.Stringer] without the push tokens.
func (d PushDevice) String() string {
	return fmt.Sprintf("PushDevice{ID:%s Client:%s Description:%q ClientVersion:%s Development:%t Token:[redacted] VoIPToken:[redacted]}",
		d.ID, d.Client, d.Description, d.ClientVersion, d.Development)
}

// PushDeviceParams describes a push device to register. Empty fields are not
// sent.
type PushDeviceParams struct {
	// Client is the platform; default "iphone" (the only known value).
	Client string
	// ClientVersion is the app version, for example "1001.125.2".
	ClientVersion string
	// Description is the device model, for example "iPhone18,1".
	Description string
	// Token is the APNs push token and VoIPToken the PushKit token.
	Token, VoIPToken string
	// Locales are BCP 47-style tags such as "en-US".
	Locales []string
	// Development selects the APNs sandbox.
	Development bool
}

const restDefaultPushClient = "iphone"

type restPushDeviceAttrs struct {
	Token                    string   `json:"token"`
	VoIPToken                string   `json:"voip_token"`
	Client                   string   `json:"client"`
	Description              string   `json:"description"`
	ClientVersion            string   `json:"client_version"`
	Locales                  []string `json:"locales"`
	Development              bool     `json:"development"`
	GraphQLID                string   `json:"graphql_id"`
	CallNotificationPushType string   `json:"call_notification_push_type"`
}

func restBoolForm(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// restPushDevice decodes a user_device_apples document. sentClient is used if
// the response does not name the client. A document without data (for
// example a 204) yields a device with only the ID.
func restPushDevice(op string, doc *jsonapi.Document, fallbackID ID, sentClient string) (*PushDevice, error) {
	d := &PushDevice{ID: fallbackID, Client: sentClient}
	if doc == nil || len(doc.Data) == 0 {
		return d, nil
	}
	res, err := doc.One()
	if err != nil {
		return nil, restFail(op, err)
	}
	var a restPushDeviceAttrs
	if err := res.DecodeAttributes(&a); err != nil {
		return nil, restFail(op, fmt.Errorf("decode push device %s: %w", res.ID, err))
	}
	d.ID = restID(res.ID)
	if a.Client != "" {
		d.Client = a.Client
	}
	d.Description, d.ClientVersion, d.Locales, d.Development = a.Description, a.ClientVersion, a.Locales, a.Development
	d.CallNotificationPushType = a.CallNotificationPushType
	d.Token, d.VoIPToken = a.Token, a.VoIPToken
	if g, err := ParseGlobalID(a.GraphQLID); err == nil {
		d.GlobalID = g
	}
	return d, nil
}

// RegisterPushDevice registers a push device (POST /mobile/v4/users/devices,
// form-encoded) and returns it. It is not idempotent and is never retried
// automatically. Keep the returned ID to [Client.TouchPushDevice] and
// [Client.DeletePushDevice] it later.
func (c *Client) RegisterPushDevice(ctx context.Context, p PushDeviceParams) (*PushDevice, error) {
	const op = "RegisterPushDevice"
	client := p.Client
	if client == "" {
		client = restDefaultPushClient
	}
	form := url.Values{"device[client]": {client}}
	for k, v := range map[string]string{
		"device[client_version]": p.ClientVersion,
		"device[description]":    p.Description,
		"device[token]":          p.Token,
		"device[voip_token]":     p.VoIPToken,
	} {
		if v != "" {
			form.Set(k, v)
		}
	}
	for _, l := range p.Locales {
		if l = strings.TrimSpace(l); l != "" {
			form.Add("device[locales][]", l)
		}
	}
	form.Set("device[development]", restBoolForm(p.Development))
	var doc jsonapi.Document
	if err := c.doForm(ctx, op, http.MethodPost, "/mobile/v4/users/devices", form, &doc); err != nil {
		return nil, err
	}
	return restPushDevice(op, &doc, 0, client)
}

// TouchPushDevice sends the heartbeat the app sends when it comes to the
// foreground (PATCH /mobile/v4/users/devices/{id} with device[client]) and
// returns the device as the server reports it.
func (c *Client) TouchPushDevice(ctx context.Context, id ID) (*PushDevice, error) {
	const op = "TouchPushDevice"
	if id <= 0 {
		return nil, restFail(op, restInvalid("device id is required"))
	}
	form := url.Values{"device[client]": {restDefaultPushClient}}
	var doc jsonapi.Document
	if err := c.doForm(ctx, op, http.MethodPatch, "/mobile/v4/users/devices/"+id.String(), form, &doc); err != nil {
		return nil, err
	}
	return restPushDevice(op, &doc, id, restDefaultPushClient)
}

// DeletePushDevice unregisters a push device (DELETE
// /mobile/v4/users/devices/{id}), as the app does on logout.
func (c *Client) DeletePushDevice(ctx context.Context, id ID) error {
	const op = "DeletePushDevice"
	if id <= 0 {
		return restFail(op, restInvalid("device id is required"))
	}
	return c.doForm(ctx, op, http.MethodDelete, "/mobile/v4/users/devices/"+id.String(), nil, nil)
}
