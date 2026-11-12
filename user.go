package butterflymx

import (
	"context"

	"github.com/stevenmirabito/butterflymx-go/internal/graphql"
)

// User is the signed-in resident account (GraphQL CurrentUser).
type User struct {
	ID          GlobalID // for example "prod-user-563494348"
	FirstName   string
	LastName    string
	Email       string
	PhoneNumber string
	AvatarURL   string
	// ContactPreference is the preferred way to be contacted, for example
	// "VIDEO_CALL". Unknown values are kept verbatim.
	ContactPreference string
	// HasDormakabaSmartLock reports whether the account has a Dormakaba lock.
	HasDormakabaSmartLock bool
	TwoFactor             TwoFactorConfig
	// AcknowledgedPrivacyPolicyVersion is the privacy-policy version the user
	// last accepted, for example "2026-01-23".
	AcknowledgedPrivacyPolicyVersion string
}

// TwoFactorConfig describes the account's two-factor authentication settings.
type TwoFactorConfig struct {
	Enabled  bool
	Required bool
	// Types lists the enrolled methods: "EMAIL", "SMS" or "AUTHENTICATOR_APP".
	// Unknown values are kept verbatim.
	Types []string
}

type gqlUserWire struct {
	ID                    GlobalID `json:"id"`
	FirstName             string   `json:"firstName"`
	LastName              string   `json:"lastName"`
	Email                 string   `json:"email"`
	PhoneNumber           string   `json:"phoneNumber"`
	AvatarURL             string   `json:"avatarUrl"`
	HasDormakabaSmartLock bool     `json:"hasDormakabaSmartLock"`
	ContactPreference     string   `json:"contactPreference"`
	TwoFactor             struct {
		Enabled  bool     `json:"enabled"`
		Required bool     `json:"required"`
		Types    []string `json:"types"`
	} `json:"twoFactorAuthenticationConfig"`
	AcknowledgedPrivacyPolicyVersion string `json:"acknowledgedPrivacyPolicyVersion"`
}

// CurrentUser returns the signed-in user.
func (c *Client) CurrentUser(ctx context.Context) (*User, error) {
	const op = "CurrentUser"
	var data struct {
		CurrentUser *gqlUserWire `json:"currentUser"`
	}
	if err := c.graphQL(ctx, op, graphql.CurrentUser, nil, &data); err != nil {
		return nil, err
	}
	w := data.CurrentUser
	if w == nil {
		return nil, gqlNotFound(op, "current user")
	}
	return &User{
		ID: w.ID, FirstName: w.FirstName, LastName: w.LastName, Email: w.Email,
		PhoneNumber: w.PhoneNumber, AvatarURL: w.AvatarURL, ContactPreference: w.ContactPreference,
		HasDormakabaSmartLock: w.HasDormakabaSmartLock,
		TwoFactor: TwoFactorConfig{
			Enabled: w.TwoFactor.Enabled, Required: w.TwoFactor.Required, Types: w.TwoFactor.Types,
		},
		AcknowledgedPrivacyPolicyVersion: w.AcknowledgedPrivacyPolicyVersion,
	}, nil
}
