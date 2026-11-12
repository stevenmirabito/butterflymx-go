package butterflymx

import (
	"context"
	"time"

	"github.com/stevenmirabito/butterflymx-go/internal/graphql"
)

// SmartLock is a third-party smart lock (Yale, Kwikset, ...) linked to the
// tenant.
//
// UNVERIFIED: the capture had no smart locks, so the field set and the types
// are modeled from the app's GraphQL fragment (SmartLockFragment), not from
// real data. Fields may be wrong.
type SmartLock struct {
	ID             GlobalID
	Name           string
	LegacyDeviceID ID
	Capabilities   []string
	AtUnitDoors    bool
	// BatteryLevel is a percentage, or nil when unknown (type unverified).
	BatteryLevel *float64
	Brand        string
	InSync       bool
	InSyncAt     *time.Time
	OutOfSyncAt  *time.Time
	WifiEnabled  bool
	Online       bool
	AccessTimes  []TimeRestriction
	Details      SmartLockDetails
}

// SmartLockDetails holds vendor-specific lock details. Only the fields for
// the vendor in Kind are set.
//
// UNVERIFIED: see [SmartLock].
type SmartLockDetails struct {
	// Kind is the GraphQL type: "YaleSmartLockDetails",
	// "KwiksetSmartLockDetails" or another value.
	Kind string
	// Yale.
	HouseID, LockID, SerialNumber string
	// Kwikset.
	DeviceID, SiteID string
}

// RemoteLock is a remotely controlled lock.
//
// UNVERIFIED: the capture had no remote locks; the fields are modeled from
// the app's GraphQL fragment (RemoteLockFragment).
type RemoteLock struct {
	ID             GlobalID
	Name           string
	LegacyDeviceID ID
	Capabilities   []string
	AtUnitDoors    bool
}

// LPRSettings are the tenant's license-plate-recognition feature flags.
type LPRSettings struct {
	// VehicleAccessToolLimit is the maximum number of vehicle access tools, or
	// nil when there is no limit or the feature is off.
	VehicleAccessToolLimit      *int
	VehicleAccessToolsEnabled   bool
	VehicleVisitorPassesEnabled bool
}

// BLECredentials are the raw Bluetooth credentials of the building for a
// registered phone. They are secrets: do not log them.
//
// This library only returns the data. Unlocking over Bluetooth is out of
// scope and not implemented.
type BLECredentials struct {
	// IntercomBLEDeviceKey is the building's intercom BLE device key (hex).
	IntercomBLEDeviceKey string
	// WavelynxEncryptedCredentialBlob and WavelynxKMD are the Wavelynx reader
	// credential (hex); empty when the building has none.
	WavelynxEncryptedCredentialBlob string
	WavelynxKMD                     string
}

type gqlSmartLockWire struct {
	ID             GlobalID                 `json:"id"`
	Name           string                   `json:"name"`
	LegacyDeviceID gqlScalar                `json:"legacyDeviceId"`
	Capabilities   []string                 `json:"capabilities"`
	AtUnitDoors    bool                     `json:"atUnitDoors"`
	BatteryLevel   *float64                 `json:"batteryLevel"`
	Brand          string                   `json:"brand"`
	InSync         bool                     `json:"inSync"`
	InSyncAt       *string                  `json:"inSyncAt"`
	OutOfSyncAt    *string                  `json:"outOfSyncAt"`
	WifiEnabled    bool                     `json:"wifiEnabled"`
	Online         bool                     `json:"online"`
	AccessTimes    []gqlTimeRestrictionWire `json:"accessTimes"`
	Details        *struct {
		Typename     string    `json:"__typename"`
		HouseID      gqlScalar `json:"houseId"`
		LockID       gqlScalar `json:"lockId"`
		SerialNumber gqlScalar `json:"serialNumber"`
		DeviceID     gqlScalar `json:"deviceId"`
		SiteID       gqlScalar `json:"siteId"`
	} `json:"details"`
}

func (w gqlSmartLockWire) convert() (SmartLock, bool) {
	if w.ID.IsZero() {
		return SmartLock{}, false
	}
	l := SmartLock{ID: w.ID, Name: w.Name, Capabilities: w.Capabilities, AtUnitDoors: w.AtUnitDoors,
		BatteryLevel: w.BatteryLevel, Brand: w.Brand, InSync: w.InSync,
		InSyncAt: gqlTimePtr(w.InSyncAt), OutOfSyncAt: gqlTimePtr(w.OutOfSyncAt),
		WifiEnabled: w.WifiEnabled, Online: w.Online, AccessTimes: gqlTimeRestrictions(w.AccessTimes)}
	l.LegacyDeviceID, _ = ParseID(string(w.LegacyDeviceID))
	if d := w.Details; d != nil {
		l.Details = SmartLockDetails{Kind: d.Typename, HouseID: string(d.HouseID), LockID: string(d.LockID),
			SerialNumber: string(d.SerialNumber), DeviceID: string(d.DeviceID), SiteID: string(d.SiteID)}
	}
	return l, true
}

type gqlRemoteLockWire struct {
	ID             GlobalID  `json:"id"`
	Name           string    `json:"name"`
	LegacyDeviceID gqlScalar `json:"legacyDeviceId"`
	Capabilities   []string  `json:"capabilities"`
	AtUnitDoors    bool      `json:"atUnitDoors"`
}

func (w gqlRemoteLockWire) convert() (RemoteLock, bool) {
	if w.ID.IsZero() {
		return RemoteLock{}, false
	}
	l := RemoteLock{ID: w.ID, Name: w.Name, Capabilities: w.Capabilities, AtUnitDoors: w.AtUnitDoors}
	l.LegacyDeviceID, _ = ParseID(string(w.LegacyDeviceID))
	return l, true
}

// SmartLocks returns the tenant's smart locks. With excludeAccessPointLocks
// set, locks that belong to building access points are left out (the app
// passes true). See [SmartLock] for the verification caveat.
func (c *Client) SmartLocks(ctx context.Context, tenantID GlobalID, excludeAccessPointLocks bool) ([]SmartLock, error) {
	const op = "TenantSmartLocks"
	if err := gqlCheckID(op, tenantID, TypeTenant); err != nil {
		return nil, err
	}
	return gqlCollect(gqlConnPages(ctx, c, op, graphql.TenantSmartLocks, "ids", tenantID,
		map[string]any{"excludeAccessPointLocks": excludeAccessPointLocks}, "smartLocks", gqlSmartLockWire.convert))
}

// RemoteLocks returns the tenant's remote locks. See [RemoteLock] for the
// verification caveat.
func (c *Client) RemoteLocks(ctx context.Context, tenantID GlobalID) ([]RemoteLock, error) {
	const op = "TenantRemoteLocks"
	if err := gqlCheckID(op, tenantID, TypeTenant); err != nil {
		return nil, err
	}
	return gqlCollect(gqlConnPages(ctx, c, op, graphql.TenantRemoteLocks, "ids", tenantID, nil,
		"remoteLocks", gqlRemoteLockWire.convert))
}

// LPRSettings returns the tenant's license-plate-recognition settings.
func (c *Client) LPRSettings(ctx context.Context, tenantID GlobalID) (*LPRSettings, error) {
	const op = "TenantLPRSettings"
	if err := gqlCheckID(op, tenantID, TypeTenant); err != nil {
		return nil, err
	}
	var data struct {
		Nodes []*struct {
			ID                          GlobalID `json:"id"`
			VehicleAccessToolLimit      *int     `json:"vehicleAccessToolLimit"`
			VehicleAccessToolsEnabled   bool     `json:"vehicleAccessToolsEnabled"`
			VehicleVisitorPassesEnabled bool     `json:"vehicleVisitorPassesEnabled"`
		} `json:"nodes"`
	}
	if err := c.graphQL(ctx, op, graphql.TenantLPRSettings, map[string]any{"ids": []string{tenantID.String()}}, &data); err != nil {
		return nil, err
	}
	if len(data.Nodes) == 0 || data.Nodes[0] == nil || data.Nodes[0].ID.IsZero() {
		return nil, gqlNotFound(op, "tenant "+tenantID.String())
	}
	n := data.Nodes[0]
	return &LPRSettings{VehicleAccessToolLimit: n.VehicleAccessToolLimit,
		VehicleAccessToolsEnabled: n.VehicleAccessToolsEnabled, VehicleVisitorPassesEnabled: n.VehicleVisitorPassesEnabled}, nil
}

// BLECredentials returns the raw Bluetooth credentials for the tenant's
// building and the registered phone userDeviceID (a "user_device_apple" ID).
// BLE unlocking itself is out of scope for this library.
func (c *Client) BLECredentials(ctx context.Context, tenantID, userDeviceID GlobalID) (*BLECredentials, error) {
	const op = "GetBLECredentials"
	if err := gqlCheckID(op, tenantID, TypeTenant); err != nil {
		return nil, err
	}
	if err := gqlCheckID(op, userDeviceID, TypeUserDeviceApple); err != nil {
		return nil, err
	}
	var data struct {
		Nodes []*struct {
			Building *struct {
				IntercomBLEDeviceKey string `json:"intercomBleDeviceKey"`
				Wavelynx             *struct {
					Blob string `json:"encryptedCredentialBlob"`
					KMD  string `json:"kmd"`
				} `json:"wavelynxReaderBleCredential"`
			} `json:"building"`
		} `json:"nodes"`
	}
	vars := map[string]any{"tenantId": tenantID.String(), "userDeviceId": userDeviceID.String()}
	if err := c.graphQL(ctx, op, graphql.GetBLECredentials, vars, &data); err != nil {
		return nil, err
	}
	if len(data.Nodes) == 0 || data.Nodes[0] == nil || data.Nodes[0].Building == nil {
		return nil, gqlNotFound(op, "tenant "+tenantID.String())
	}
	b := data.Nodes[0].Building
	out := &BLECredentials{IntercomBLEDeviceKey: b.IntercomBLEDeviceKey}
	if b.Wavelynx != nil {
		out.WavelynxEncryptedCredentialBlob, out.WavelynxKMD = b.Wavelynx.Blob, b.Wavelynx.KMD
	}
	return out, nil
}
