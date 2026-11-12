package butterflymx

import (
	"context"
	"iter"
	"time"

	"github.com/stevenmirabito/butterflymx-go/internal/graphql"
)

// NodeRef is a reference to a GraphQL node: an ID, a name and the node's type.
type NodeRef struct {
	ID   GlobalID
	Name string
	// Kind is the GraphQL type name ("AccessPoint", "Intercom",
	// "CloudBasedAccessController", ...) when the API provided it.
	Kind string
}

// DoorRelease is one door-open event in the tenant's history.
type DoorRelease struct {
	ID       GlobalID // note: the type tag is spelled "door_relase" by the server
	LoggedAt time.Time
	ImageURL string
	// Type is for example "VISITOR".
	Type string
	// Method is for example SWIPE_TO_OPEN, RFID, MOBILE_CALL or VIRTUAL_KEY_PIN.
	// Unknown values are kept verbatim.
	Method       string
	LicensePlate *LicensePlate
	AccessPoint  NodeRef
	Device       NodeRef
}

// LicensePlate is a recognized vehicle plate attached to a door release.
type LicensePlate struct {
	ID            GlobalID
	Number        string
	IssuerName    string
	IssuerCountry string
}

// Call is an intercom call in the tenant's history.
type Call struct {
	ID       GlobalID
	GUID     string
	LoggedAt time.Time
	ImageURL string
	// NotificationType is for example "VISITOR" or "DELIVERY".
	NotificationType string
	// DisplayStatus is for example "OPENED_DOOR".
	DisplayStatus string
	Device        NodeRef
}

// Message is a text message sent to the tenant.
type Message struct {
	ID        GlobalID
	Title     string
	Body      string
	CreatedAt time.Time
	LogoURL   string
	ImageURL  string
	Origin    string
	// SourceName is the name of the sending device, when the source is a device.
	SourceName string
}

// MessageOptions tunes Messages.
type MessageOptions struct {
	// ImageSize selects the image variant: "thumb" (default) or "medium".
	ImageSize string
}

type gqlNodeRefWire struct {
	Typename string   `json:"__typename"`
	ID       GlobalID `json:"id"`
	Name     string   `json:"name"`
}

func (w gqlNodeRefWire) convert() NodeRef { return NodeRef{ID: w.ID, Name: w.Name, Kind: w.Typename} }

type gqlDoorReleaseWire struct {
	ID           GlobalID `json:"id"`
	LoggedAt     string   `json:"loggedAt"`
	ImageURL     string   `json:"imageUrl"`
	Type         string   `json:"type"`
	Method       string   `json:"method"`
	LicensePlate *struct {
		ID     GlobalID `json:"id"`
		Number string   `json:"number"`
		Issuer struct {
			Name    string `json:"name"`
			Country string `json:"country"`
		} `json:"issuer"`
	} `json:"licensePlate"`
	AccessPoint gqlNodeRefWire `json:"accessPoint"`
	Device      gqlNodeRefWire `json:"device"`
}

func (w gqlDoorReleaseWire) convert() (DoorRelease, bool) {
	if w.ID.IsZero() {
		return DoorRelease{}, false
	}
	d := DoorRelease{ID: w.ID, LoggedAt: gqlTime(w.LoggedAt), ImageURL: w.ImageURL, Type: w.Type,
		Method: w.Method, AccessPoint: w.AccessPoint.convert(), Device: w.Device.convert()}
	if p := w.LicensePlate; p != nil {
		d.LicensePlate = &LicensePlate{ID: p.ID, Number: p.Number, IssuerName: p.Issuer.Name, IssuerCountry: p.Issuer.Country}
	}
	return d, true
}

type gqlCallWire struct {
	ID               GlobalID       `json:"id"`
	GUID             string         `json:"guid"`
	LoggedAt         string         `json:"loggedAt"`
	ImageURL         string         `json:"imageUrl"`
	NotificationType string         `json:"notificationType"`
	DisplayStatus    string         `json:"displayStatus"`
	Device           gqlNodeRefWire `json:"device"`
}

func (w gqlCallWire) convert() (Call, bool) {
	if w.ID.IsZero() {
		return Call{}, false
	}
	return Call{ID: w.ID, GUID: w.GUID, LoggedAt: gqlTime(w.LoggedAt), ImageURL: w.ImageURL,
		NotificationType: w.NotificationType, DisplayStatus: w.DisplayStatus, Device: w.Device.convert()}, true
}

type gqlMessageWire struct {
	ID        GlobalID `json:"id"`
	Title     string   `json:"title"`
	Body      string   `json:"body"`
	CreatedAt string   `json:"createdAt"`
	LogoURL   string   `json:"logoUrl"`
	ImageURL  string   `json:"imageUrl"`
	Origin    string   `json:"origin"`
	Source    *struct {
		Name string `json:"name"`
	} `json:"source"`
}

// convert drops nodes that are not text messages (they carry no id).
func (w gqlMessageWire) convert() (Message, bool) {
	if w.ID.IsZero() {
		return Message{}, false
	}
	m := Message{ID: w.ID, Title: w.Title, Body: w.Body, CreatedAt: gqlTime(w.CreatedAt),
		LogoURL: w.LogoURL, ImageURL: w.ImageURL, Origin: w.Origin}
	if w.Source != nil {
		m.SourceName = w.Source.Name
	}
	return m, true
}

// DoorReleases iterates over the tenant's door-open history, newest first. It
// fetches pages lazily; stop iterating to stop fetching. Errors (including
// ErrIDType for a wrong tenantID and ErrNotFound for an unknown tenant) are
// yielded as the final element.
func (c *Client) DoorReleases(ctx context.Context, tenantID GlobalID) iter.Seq2[DoorRelease, error] {
	const op = "TenantDoorReleases"
	if err := gqlCheckID(op, tenantID, TypeTenant); err != nil {
		return gqlFailSeq[DoorRelease](err)
	}
	return gqlConnPages(ctx, c, op, graphql.TenantDoorReleases, "tenantIds", tenantID, nil,
		"doorReleases", gqlDoorReleaseWire.convert)
}

// Calls iterates over the tenant's intercom call history, newest first. See
// [Client.DoorReleases] for the iteration semantics.
func (c *Client) Calls(ctx context.Context, tenantID GlobalID) iter.Seq2[Call, error] {
	const op = "TenantCalls"
	if err := gqlCheckID(op, tenantID, TypeTenant); err != nil {
		return gqlFailSeq[Call](err)
	}
	return gqlConnPages(ctx, c, op, graphql.TenantCalls, "tenantIds", tenantID, nil,
		"calls", gqlCallWire.convert)
}

// Messages iterates over the tenant's messages, newest first. opts may be
// nil. See [Client.DoorReleases] for the iteration semantics.
func (c *Client) Messages(ctx context.Context, tenantID GlobalID, opts *MessageOptions) iter.Seq2[Message, error] {
	const op = "TenantMessages"
	if err := gqlCheckID(op, tenantID, TypeTenant); err != nil {
		return gqlFailSeq[Message](err)
	}
	var extra map[string]any
	if opts != nil && opts.ImageSize != "" {
		extra = map[string]any{"imageSize": opts.ImageSize}
	}
	return gqlConnPages(ctx, c, op, graphql.TenantMessages, "tenantIds", tenantID, extra,
		"messages", gqlMessageWire.convert)
}
