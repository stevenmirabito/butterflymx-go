package butterflymx

import (
	"context"
	"errors"
	"testing"
)

func TestGQLLocksFixtures(t *testing.T) {
	c, seen := gqlTestOps(t, map[string]func(map[string]any) []byte{
		"TenantSmartLocks":  gqlTestFixture(t, "TenantSmartLocks"),
		"TenantRemoteLocks": gqlTestFixture(t, "TenantRemoteLocks"),
		"TenantLPRSettings": gqlTestFixture(t, "TenantLPRSettings"),
		"GetBLECredentials": gqlTestFixture(t, "GetBLECredentials"),
	})
	ctx := context.Background()
	tid := gqlTestTenantID()

	sl, err := c.SmartLocks(ctx, tid, true)
	if err != nil || len(sl) != 0 {
		t.Errorf("SmartLocks = %v, %v", sl, err)
	}
	if (*seen)[0]["excludeAccessPointLocks"] != true {
		t.Errorf("vars = %v", (*seen)[0])
	}
	rl, err := c.RemoteLocks(ctx, tid)
	if err != nil || len(rl) != 0 {
		t.Errorf("RemoteLocks = %v, %v", rl, err)
	}
	lpr, err := c.LPRSettings(ctx, tid)
	if err != nil || lpr.VehicleAccessToolLimit != nil || lpr.VehicleAccessToolsEnabled || lpr.VehicleVisitorPassesEnabled {
		t.Errorf("LPRSettings = %+v, %v", lpr, err)
	}
	dev := NewGlobalID("prod", TypeUserDeviceApple, 65794426)
	ble, err := c.BLECredentials(ctx, tid, dev)
	if err != nil {
		t.Fatal(err)
	}
	if ble.IntercomBLEDeviceKey != "f1cd8b9066370a049888dc1e2f9a573a" || ble.WavelynxKMD != "5e6493ae83802f6c0bf92140c3d59194" ||
		len(ble.WavelynxEncryptedCredentialBlob) != 128 {
		t.Errorf("ble = %+v", ble)
	}
	last := (*seen)[len(*seen)-1]
	if last["tenantId"] != "prod-tenant-7754340" || last["userDeviceId"] != "prod-user_device_apple-65794426" {
		t.Errorf("ble vars = %v", last)
	}
}

func TestGQLLocksDecodeNodes(t *testing.T) {
	c, _ := gqlTestOps(t, map[string]func(map[string]any) []byte{
		"TenantSmartLocks": func(map[string]any) []byte {
			return []byte(`{"data":{"nodes":[{"id":"prod-tenant-7754340","smartLocks":{"pageInfo":{"hasNextPage":false},"nodes":[
				{"id":"prod-smart_lock-1","name":"Yale","legacyDeviceId":42,"capabilities":["LOCK"],"atUnitDoors":true,"batteryLevel":87.5,"brand":"YALE","inSync":true,"inSyncAt":"2026-01-02T03:04:05Z","outOfSyncAt":null,"wifiEnabled":true,"online":true,
				 "accessTimes":[{"from":"08:00","to":"17:00","days":["FRIDAY"]}],"details":{"__typename":"YaleSmartLockDetails","houseId":"h","lockId":"l","serialNumber":"s"}},
				{"id":"prod-smart_lock-2","details":{"__typename":"KwiksetSmartLockDetails","deviceId":"d","siteId":9}}]}}]}}`)
		},
		"TenantRemoteLocks": func(map[string]any) []byte {
			return []byte(`{"data":{"nodes":[{"id":"prod-tenant-7754340","remoteLocks":{"pageInfo":{"hasNextPage":false},"nodes":[{"id":"prod-remote_lock-1","name":"R","legacyDeviceId":"7","capabilities":["X"],"atUnitDoors":false}]}}]}}`)
		},
		"TenantLPRSettings": func(map[string]any) []byte {
			return []byte(`{"data":{"nodes":[{"id":"prod-tenant-7754340","vehicleAccessToolLimit":3,"vehicleAccessToolsEnabled":true,"vehicleVisitorPassesEnabled":true}]}}`)
		},
	})
	ctx := context.Background()
	sl, err := c.SmartLocks(ctx, gqlTestTenantID(), false)
	if err != nil || len(sl) != 2 {
		t.Fatalf("SmartLocks = %+v, %v", sl, err)
	}
	a := sl[0]
	if a.Name != "Yale" || a.LegacyDeviceID != 42 || a.BatteryLevel == nil || *a.BatteryLevel != 87.5 || a.InSyncAt == nil || a.OutOfSyncAt != nil ||
		len(a.AccessTimes) != 1 || a.AccessTimes[0].Days[0] != Friday || a.Details.Kind != "YaleSmartLockDetails" || a.Details.LockID != "l" {
		t.Errorf("a = %+v", a)
	}
	if sl[1].Details.SiteID != "9" || sl[1].Details.DeviceID != "d" {
		t.Errorf("b = %+v", sl[1])
	}
	rl, err := c.RemoteLocks(ctx, gqlTestTenantID())
	if err != nil || len(rl) != 1 || rl[0].LegacyDeviceID != 7 || rl[0].Name != "R" {
		t.Errorf("RemoteLocks = %+v, %v", rl, err)
	}
	lpr, err := c.LPRSettings(ctx, gqlTestTenantID())
	if err != nil || lpr.VehicleAccessToolLimit == nil || *lpr.VehicleAccessToolLimit != 3 || !lpr.VehicleAccessToolsEnabled {
		t.Errorf("LPR = %+v, %v", lpr, err)
	}
}

func TestGQLLocksErrors(t *testing.T) {
	c, seen := gqlTestOps(t, map[string]func(map[string]any) []byte{
		"GetBLECredentials": func(map[string]any) []byte { return []byte(`{"data":{"nodes":[null]}}`) },
		"TenantLPRSettings": func(map[string]any) []byte { return []byte(`{"data":{"nodes":[null]}}`) },
	})
	ctx := context.Background()
	ap := NewGlobalID("prod", TypeAccessPoint, 1)
	tid := gqlTestTenantID()
	dev := NewGlobalID("prod", TypeUserDeviceApple, 1)
	if _, err := c.SmartLocks(ctx, ap, true); !errors.Is(err, ErrIDType) {
		t.Errorf("SmartLocks: %v", err)
	}
	if _, err := c.RemoteLocks(ctx, ap); !errors.Is(err, ErrIDType) {
		t.Errorf("RemoteLocks: %v", err)
	}
	if _, err := c.LPRSettings(ctx, ap); !errors.Is(err, ErrIDType) {
		t.Errorf("LPRSettings: %v", err)
	}
	if _, err := c.BLECredentials(ctx, ap, dev); !errors.Is(err, ErrIDType) {
		t.Errorf("BLE tenant: %v", err)
	}
	if _, err := c.BLECredentials(ctx, tid, tid); !errors.Is(err, ErrIDType) {
		t.Errorf("BLE device: %v", err)
	}
	if len(*seen) != 0 {
		t.Errorf("requests = %d", len(*seen))
	}
	if _, err := c.BLECredentials(ctx, tid, dev); !errors.Is(err, ErrNotFound) {
		t.Errorf("BLE null: %v", err)
	}
	if _, err := c.LPRSettings(ctx, tid); !errors.Is(err, ErrNotFound) {
		t.Errorf("LPR null: %v", err)
	}
}
