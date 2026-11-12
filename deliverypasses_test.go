package butterflymx

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// restTestDeliveryPassDoc renders a GET /v3/keychains/75337466 response.
func restTestDeliveryPassDoc(name, endsAt string) []byte {
	return fmt.Appendf(nil, `{"data":{"id":"75337466","type":"keychains","attributes":{
		"name":%q,"weekdays":[],"starts_at":"2026-11-12T05:12:03Z","ends_at":%q,"time_from":"21:12","time_to":"21:12",
		"kind":"delivery_pass","start_date":"2026-11-11","end_date":"2026-12-11","allow_unit_access":false},
		"relationships":{"virtual_keys":{"data":[{"id":"55244830","type":"virtual_keys"}]},"devices":{"data":[]}}},
		"included":[{"id":"55244830","type":"virtual_keys","attributes":{"name":%q,"pin":"951955"},"relationships":{}}]}`,
		name, endsAt, name)
}

func TestRESTCreateDeliveryPassShape(t *testing.T) {
	srv, reqs := restTestServer(t, func(restTestReq) (int, []byte) {
		return http.StatusCreated, restTestRespBody(t, "post-keychains-delivery-pass-201")
	})
	c, _ := newTestClient(t, srv, nil)
	k, err := c.CreateDeliveryPass(context.Background(), DeliveryPassParams{TenantID: restTestTenant(7754340)})
	if err != nil {
		t.Fatal(err)
	}
	got := reqs()
	if len(got) != 1 || got[0].Method != http.MethodPost || got[0].Path != "/v3/keychains/delivery_pass" {
		t.Fatalf("requests = %+v", got)
	}
	restTestEqualJSON(t, got[0].Body, restTestReqBody(t, "post-keychains-delivery-pass-201"))

	if k.ID != 75337466 || k.Kind != KindDeliveryPass || k.Name != "Delivery Pass" ||
		k.EndsAt.Sub(k.StartsAt) != 30*24*time.Hour || len(k.Devices) != 4 {
		t.Errorf("pass = %+v", k)
	}
	if len(k.VirtualKeys) != 1 || k.VirtualKeys[0].PIN.Reveal() != "951955" || k.VirtualKeys[0].Email != "" || k.VirtualKeys[0].SMSNumber != "" {
		t.Errorf("key = %+v", k.VirtualKeys)
	}
}

func TestRESTCreateDeliveryPassNameAndIDs(t *testing.T) {
	srv, reqs := restTestServer(t, func(restTestReq) (int, []byte) {
		return http.StatusCreated, restTestRespBody(t, "post-keychains-delivery-pass-201")
	})
	c, _ := newTestClient(t, srv, nil)
	if _, err := c.CreateDeliveryPass(context.Background(), DeliveryPassParams{
		TenantID: restTestTenant(7754340), Name: "Amazon",
	}); err != nil {
		t.Fatal(err)
	}
	// access_points is always sent empty: delivery passes cover every door.
	want := restTestMutate(t, restTestReqBody(t, "post-keychains-delivery-pass-201"), func(m map[string]any) {
		restTestDig(m, "data", "attributes").(map[string]any)["name"] = "Amazon"
	})
	restTestEqualJSON(t, reqs()[0].Body, want)

	// A wrong ID type fails without a request.
	n := len(reqs())
	_, err := c.CreateDeliveryPass(context.Background(), DeliveryPassParams{TenantID: restTestAPs(1)[0]})
	restTestErrIs(t, err, ErrIDType)
	if len(reqs()) != n {
		t.Error("requests sent for invalid IDs")
	}
}

// restTestUpdateServer serves the GET before the PATCH with before and after
// it with after (the PATCH answers 204 with no body, like the real API).
func restTestUpdateServer(t *testing.T, before, after []byte) (*Client, func() []restTestReq) {
	t.Helper()
	patched := false
	srv, reqs := restTestServer(t, func(r restTestReq) (int, []byte) {
		switch r.Method {
		case http.MethodPatch:
			patched = true
			return http.StatusNoContent, nil
		case http.MethodGet:
			if patched {
				return http.StatusOK, after
			}
			return http.StatusOK, before
		}
		return http.StatusInternalServerError, nil
	})
	c, _ := newTestClient(t, srv, nil)
	return c, reqs
}

func TestRESTUpdateDeliveryPassRenameShape(t *testing.T) {
	c, reqs := restTestUpdateServer(t,
		restTestDeliveryPassDoc("Delivery Pass", "2026-12-12T05:12:03Z"),
		restTestDeliveryPassDoc("Test Delivery", "2026-12-12T05:12:03Z"))
	k, err := c.UpdateDeliveryPass(context.Background(), 75337466, DeliveryPassUpdate{Name: restPtr("Test Delivery")})
	if err != nil {
		t.Fatal(err)
	}
	got := reqs()
	if len(got) != 3 || got[0].Method != http.MethodGet || got[1].Method != http.MethodPatch || got[2].Method != http.MethodGet {
		t.Fatalf("requests = %+v", got)
	}
	if got[1].Path != "/v3/keychains/delivery_pass/75337466" || got[2].Path != "/v3/keychains/75337466" {
		t.Errorf("paths = %q, %q", got[1].Path, got[2].Path)
	}
	restTestEqualJSON(t, got[1].Body, restTestReqBody(t, "patch-keychains-delivery-pass-204-rename"))
	if k.Name != "Test Delivery" || len(k.VirtualKeys) != 1 || k.VirtualKeys[0].Name != "Test Delivery" {
		t.Errorf("pass after update = %+v", k)
	}
}

func TestRESTExtendDeliveryPassShape(t *testing.T) {
	c, reqs := restTestUpdateServer(t,
		restTestDeliveryPassDoc("Test Delivery", "2026-12-12T05:12:03Z"),
		restTestDeliveryPassDoc("Test Delivery", "2027-01-11T05:12:03Z"))
	k, err := c.ExtendDeliveryPass(context.Background(), 75337466, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got := reqs()
	if len(got) != 3 || got[1].Method != http.MethodPatch {
		t.Fatalf("requests = %+v", got)
	}
	// The app sends ends_at as "2027-01-10T21:12:03-0800"; this library sends
	// the same instant in UTC.
	want := restTestMutate(t, restTestReqBody(t, "patch-keychains-delivery-pass-204-extend"), func(m map[string]any) {
		attrs := restTestDig(m, "data", "attributes").(map[string]any)
		if attrs["ends_at"] != "2027-01-10T21:12:03-0800" {
			t.Fatalf("fixture ends_at = %v", attrs["ends_at"])
		}
		attrs["ends_at"] = "2027-01-11T05:12:03Z"
	})
	restTestEqualJSON(t, got[1].Body, want)
	if !k.EndsAt.Equal(restTestParseTime(t, "2027-01-10T21:12:03-08:00")) {
		t.Errorf("EndsAt = %v", k.EndsAt)
	}

	// Setting EndsAt directly gives the same body.
	c, reqs = restTestUpdateServer(t,
		restTestDeliveryPassDoc("Test Delivery", "2026-12-12T05:12:03Z"),
		restTestDeliveryPassDoc("Test Delivery", "2027-01-11T05:12:03Z"))
	at := restTestParseTime(t, "2027-01-10T21:12:03-08:00")
	if _, err := c.UpdateDeliveryPass(context.Background(), 75337466, DeliveryPassUpdate{EndsAt: &at}); err != nil {
		t.Fatal(err)
	}
	restTestEqualJSON(t, reqs()[1].Body, want)
}

func TestRESTUpdateDeliveryPassErrors(t *testing.T) {
	ctx := context.Background()
	c, reqs := restTestUpdateServer(t, restTestDeliveryPassDoc("Delivery Pass", "2026-12-12T05:12:03Z"), nil)

	_, err := c.UpdateDeliveryPass(ctx, 75337466, DeliveryPassUpdate{})
	restTestErrIs(t, err, ErrValidation)
	_, err = c.UpdateDeliveryPass(ctx, 0, DeliveryPassUpdate{Name: restPtr("x")})
	restTestErrIs(t, err, ErrValidation)
	if len(reqs()) != 0 {
		t.Error("requests sent before validation")
	}
	_, err = c.UpdateDeliveryPass(ctx, 75337466, DeliveryPassUpdate{Name: restPtr(" ")})
	restTestErrIs(t, err, ErrValidation)
	early := restTestParseTime(t, "2026-11-01T00:00:00Z")
	_, err = c.UpdateDeliveryPass(ctx, 75337466, DeliveryPassUpdate{EndsAt: &early})
	restTestErrIs(t, err, ErrValidation)
	_, err = c.ExtendDeliveryPass(ctx, 75337466, -60*24*time.Hour)
	restTestErrIs(t, err, ErrValidation)
	for _, r := range reqs() {
		if r.Method == http.MethodPatch {
			t.Fatal("PATCH sent despite validation failure")
		}
	}

	// A guest pass is refused.
	c2, reqs2 := restTestUpdateServer(t, restTestRespBody(t, "get-keychains-custom-200-existing"), nil)
	_, err = c2.ExtendDeliveryPass(ctx, 85303961, time.Hour)
	restTestErrIs(t, err, ErrValidation)
	if len(reqs2()) != 1 {
		t.Errorf("requests = %d, want only the read", len(reqs2()))
	}
}

func TestRESTDeliveryPassLifecycle(t *testing.T) {
	w := restTestNewWorld(t)
	ctx := context.Background()

	dp, err := w.c.CreateDeliveryPass(ctx, DeliveryPassParams{TenantID: w.tenant})
	if err != nil {
		t.Fatal(err)
	}
	if dp.Kind != KindDeliveryPass || dp.Name != "Delivery Pass" || dp.EndsAt.Sub(dp.StartsAt) != 30*24*time.Hour ||
		len(dp.VirtualKeys) != 1 || !dp.VirtualKeys[0].PIN.Valid() || dp.VirtualKeys[0].Email != "" || len(dp.Devices) == 0 {
		t.Fatalf("delivery pass = %+v", dp)
	}
	if cs, ok := dp.Schedule().(CustomSchedule); !ok || !cs.EndsAt.Equal(dp.EndsAt) {
		t.Errorf("Schedule() = %#v", dp.Schedule())
	}

	// It is listed as a delivery pass among the active ones.
	list, err := w.c.Keychains(ctx, w.tenant, KeychainFilter{Kinds: []KeychainKind{KindDeliveryPass}})
	if err != nil {
		t.Fatal(err)
	}
	if !restTestHas(list, dp.ID) {
		t.Errorf("delivery passes = %v", restTestIDs(list))
	}

	// Rename: the key follows.
	k, err := w.c.UpdateDeliveryPass(ctx, dp.ID, DeliveryPassUpdate{Name: restPtr("Amazon")})
	if err != nil {
		t.Fatal(err)
	}
	if k.Name != "Amazon" || k.VirtualKeys[0].Name != "Amazon" || !k.EndsAt.Equal(dp.EndsAt) {
		t.Errorf("after rename = %+v", k)
	}

	// Extend by two days; the PIN is unchanged.
	k, err = w.c.ExtendDeliveryPass(ctx, dp.ID, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if want := dp.EndsAt.Add(48 * time.Hour); !k.EndsAt.Equal(want) || k.Name != "Amazon" || k.VirtualKeys[0].PIN != dp.VirtualKeys[0].PIN {
		t.Errorf("after extend: EndsAt = %v, want %v; pass = %+v", k.EndsAt, want, k)
	}

	// Using the key consumes it.
	if err := w.s.AddDoorRelease(dp.VirtualKeys[0].ID.String(), w.seed.VirtualKeyAccessPoints()[0].ID); err != nil {
		t.Fatal(err)
	}
	if k, err = w.c.Keychain(ctx, dp.ID); err != nil {
		t.Fatal(err)
	}
	if vk := k.VirtualKeys[0]; vk.UsedAt == nil || vk.OneTimeKeyUsedAt == nil || len(vk.Releases) != 1 {
		t.Errorf("used key = %+v", vk)
	}

	// Delete.
	if err := w.c.DeleteKeychain(ctx, dp.ID); err != nil {
		t.Fatal(err)
	}
	_, err = w.c.Keychain(ctx, dp.ID)
	restTestErrIs(t, err, ErrNotFound)
	_, err = w.c.ExtendDeliveryPass(ctx, dp.ID, time.Hour)
	restTestErrIs(t, err, ErrNotFound)

	// A second pass is independent.
	dp2, err := w.c.CreateDeliveryPass(ctx, DeliveryPassParams{TenantID: w.tenant, Name: "Groceries"})
	if err != nil {
		t.Fatal(err)
	}
	if dp2.Name != "Groceries" {
		t.Errorf("name = %q", dp2.Name)
	}
}
