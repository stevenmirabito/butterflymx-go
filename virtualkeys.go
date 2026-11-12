package butterflymx

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/stevenmirabito/butterflymx-go/internal/jsonapi"
)

// VirtualKey is one credential inside a keychain, issued to one recipient. A
// guest uses the PIN or the QR code at the door; ButterflyMX sends the key to
// the recipient by email or SMS.
//
// PIN is redacted in logs and when printed (see [PIN]).
type VirtualKey struct {
	ID ID
	// Name is the recipient's name (for a delivery pass, the pass name).
	Name string
	// Email and SMSNumber hold the delivery address; at most one is set. The
	// SMS number is in E.164 form. Both are empty for a delivery pass.
	Email, SMSNumber string
	// PIN is the 6-digit door code; it can have leading zeros.
	PIN PIN
	// QRCodeURL is the URL of the QR code image. The image is publicly
	// readable without authentication, so treat the URL like the PIN.
	QRCodeURL string
	// InstructionsURL is a public page for the guest.
	InstructionsURL string

	// SentAt is when ButterflyMX delivered the key: nil right after creation,
	// set asynchronously within seconds. Always nil for delivery passes.
	SentAt *time.Time
	// UsedAt and OneTimeKeyUsedAt are set only on one-time keys (delivery
	// passes) once they are consumed. They are not "last used" fields: for a
	// guest key use Releases (spec §7.5).
	UsedAt, OneTimeKeyUsedAt *time.Time
	SyncedWithRemoteLock     bool

	// Releases are the door releases made with this key. They are filled in
	// only by calls that include them: [Client.Keychain] and [Client.Keychains].
	Releases []KeyRelease
}

// KeyRelease is a log entry recording that a door was opened with a virtual
// key.
type KeyRelease struct {
	ID ID
	// ReleaseMethod is how the door was opened, for example "virtual_key_pin"
	// or "qr_key". Unknown values are preserved.
	ReleaseMethod string
	// DoorReleaseType is, for example, "visitor".
	DoorReleaseType string
	PanelUserType   string
	// Name is the name logged with the release.
	Name                string
	CreatedAt, LoggedAt time.Time
	// ThumbURL and MediumURL are camera snapshot image URLs, if any.
	ThumbURL, MediumURL string
	// Panel is the intercom panel the release happened at; nil when the
	// response did not include it or the door has no panel.
	Panel *KeychainDevice
}

type restVirtualKeyAttrs struct {
	Name                 string `json:"name"`
	Email                string `json:"email"`
	SMSNumber            string `json:"sms_number"`
	PIN                  string `json:"pin"`
	QRCodeImageURL       string `json:"qr_code_image_url"`
	InstructionsURL      string `json:"instructions_url"`
	SentAt               string `json:"sent_at"`
	UsedAt               string `json:"used_at"`
	OneTimeKeyUsedAt     string `json:"one_time_key_used_at"`
	SyncedWithRemoteLock bool   `json:"synced_with_remote_lock"`
}

type restReleaseAttrs struct {
	ReleaseMethod   string `json:"release_method"`
	DoorReleaseType string `json:"door_release_type"`
	PanelUserType   string `json:"panel_user_type"`
	Name            string `json:"name"`
	CreatedAt       string `json:"created_at"`
	LoggedAt        string `json:"logged_at"`
	ThumbURL        string `json:"thumb_url"`
	MediumURL       string `json:"medium_url"`
}

// restBuildVirtualKey converts a virtual_keys resource; door releases are
// resolved through idx.
func restBuildVirtualKey(r jsonapi.Resource, idx *jsonapi.Index) (VirtualKey, error) {
	var a restVirtualKeyAttrs
	if err := r.DecodeAttributes(&a); err != nil {
		return VirtualKey{}, fmt.Errorf("decode virtual key %s: %w", r.ID, err)
	}
	vk := VirtualKey{
		ID: restID(r.ID), Name: a.Name, Email: a.Email, SMSNumber: a.SMSNumber, PIN: PIN(a.PIN),
		QRCodeURL: a.QRCodeImageURL, InstructionsURL: a.InstructionsURL,
		SentAt: restOptTime(a.SentAt), UsedAt: restOptTime(a.UsedAt), OneTimeKeyUsedAt: restOptTime(a.OneTimeKeyUsedAt),
		SyncedWithRemoteLock: a.SyncedWithRemoteLock,
	}
	ids, err := r.Relationships["door_releases"].Many()
	if err != nil {
		return VirtualKey{}, fmt.Errorf("virtual key %s: door_releases: %w", r.ID, err)
	}
	for _, id := range ids {
		res, ok := idx.Get(id)
		if !ok {
			continue // releases are only present when requested
		}
		var ra restReleaseAttrs
		if err := res.DecodeAttributes(&ra); err != nil {
			return VirtualKey{}, fmt.Errorf("decode door release %s: %w", id.ID, err)
		}
		rel := KeyRelease{
			ID: restID(id.ID), ReleaseMethod: ra.ReleaseMethod, DoorReleaseType: ra.DoorReleaseType,
			PanelUserType: ra.PanelUserType, Name: ra.Name,
			CreatedAt: restTime(ra.CreatedAt), LoggedAt: restTime(ra.LoggedAt),
			ThumbURL: ra.ThumbURL, MediumURL: ra.MediumURL,
		}
		if pid, err := res.Relationships["panel"].One(); err == nil && pid != nil {
			if d, err := restDevice(*pid, idx); err == nil {
				rel.Panel = &d
			}
		}
		vk.Releases = append(vk.Releases, rel)
	}
	return vk, nil
}

// AddVirtualKeys issues one more virtual key per recipient on an existing
// keychain (POST /v3/keychains/{id}/virtual_keys) and returns the new keys in
// recipient order, each with its PIN, QR code URL and instructions URL.
// ButterflyMX delivers each key to its recipient.
//
// Recipients are validated before anything is sent (unless
// [Options.SkipClientValidation] is set). Like [Client.CreateKeychain]
// this is not idempotent and is never retried automatically; after an
// ambiguous failure, re-read the keychain with [Client.Keychain] to see which
// keys exist. Delivery passes cannot take recipients.
func (c *Client) AddVirtualKeys(ctx context.Context, keychainID ID, recipients ...Recipient) ([]VirtualKey, error) {
	const op = "AddVirtualKeys"
	if keychainID <= 0 {
		return nil, restFail(op, restInvalid("keychain id is required"))
	}
	skip := c.cfg.SkipClientValidation
	if len(recipients) == 0 && !skip {
		return nil, restFail(op, restInvalid("at least one recipient is required"))
	}
	recips, err := restRecipients(recipients, skip)
	if err != nil {
		return nil, restFail(op, err)
	}
	// The app sends the other attributes as explicit nulls.
	attrs := struct {
		Recipients     []restRecipient `json:"recipients"`
		Name           *string         `json:"name"`
		Email          *string         `json:"email"`
		SMSNumber      *string         `json:"sms_number"`
		PIN            *string         `json:"pin"`
		UsedAt         *string         `json:"used_at"`
		QRCodeImageURL *string         `json:"qr_code_image_url"`
	}{Recipients: recips}
	doc, err := c.jsonAPI(ctx, op, http.MethodPost, "/v3/keychains/"+keychainID.String()+"/virtual_keys", nil,
		&jsonapi.ResourceObject{Type: "virtual_keys", Attributes: attrs})
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, restFail(op, fmt.Errorf("empty response"))
	}
	res, err := doc.Many()
	if err != nil {
		return nil, restFail(op, err)
	}
	idx := doc.Index()
	keys := make([]VirtualKey, 0, len(res))
	for _, r := range res {
		vk, err := restBuildVirtualKey(r, idx)
		if err != nil {
			return nil, restFail(op, err)
		}
		keys = append(keys, vk)
	}
	return keys, nil
}

// RevokeVirtualKey revokes one key of a keychain without touching its other
// keys (DELETE /v3/keychains/{keychain}/virtual_keys/{key}).
func (c *Client) RevokeVirtualKey(ctx context.Context, keychainID, virtualKeyID ID) error {
	const op = "RevokeVirtualKey"
	if keychainID <= 0 || virtualKeyID <= 0 {
		return restFail(op, restInvalid("keychain id and virtual key id are required"))
	}
	_, err := c.jsonAPI(ctx, op, http.MethodDelete,
		"/v3/keychains/"+keychainID.String()+"/virtual_keys/"+virtualKeyID.String(), nil, nil)
	return err
}
