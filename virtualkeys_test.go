package butterflymx

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

func TestRESTAddVirtualKeysShape(t *testing.T) {
	srv, reqs := restTestServer(t, func(restTestReq) (int, []byte) {
		return http.StatusCreated, restTestRespBody(t, "post-keychains-virtual-keys-201")
	})
	c, _ := newTestClient(t, srv, nil)
	keys, err := c.AddVirtualKeys(context.Background(), 85303961, SMSRecipient("Resident Example", "(555) 555-0100"))
	if err != nil {
		t.Fatal(err)
	}
	got := reqs()
	if len(got) != 1 || got[0].Method != http.MethodPost || got[0].Path != "/v3/keychains/85303961/virtual_keys" {
		t.Fatalf("requests = %+v", got)
	}
	// The app sends the number as typed; this library sends E.164. Everything
	// else is identical.
	want := restTestMutate(t, restTestReqBody(t, "post-keychains-virtual-keys-201"), func(m map[string]any) {
		r := restTestDig(m, "data", "attributes", "recipients", 0).(map[string]any)
		if r["deliver_to"] != "(555) 555-0100" {
			t.Fatalf("fixture deliver_to = %v", r["deliver_to"])
		}
		r["deliver_to"] = "+15555550100"
	})
	restTestEqualJSON(t, got[0].Body, want)

	if len(keys) != 1 {
		t.Fatalf("keys = %d", len(keys))
	}
	k := keys[0]
	if k.ID != 12915969 || k.Name != "Resident Example" || k.SMSNumber != "+15555550100" || k.Email != "" ||
		k.PIN.Reveal() != "112358" || k.QRCodeURL == "" || k.InstructionsURL == "" || k.SentAt != nil {
		t.Errorf("key = %+v", k)
	}
}

func TestRESTAddVirtualKeysValidation(t *testing.T) {
	srv, reqs := restTestServer(t, func(restTestReq) (int, []byte) { return http.StatusInternalServerError, nil })
	c, _ := newTestClient(t, srv, nil)
	ctx := context.Background()
	_, err := c.AddVirtualKeys(ctx, 1)
	restTestErrIs(t, err, ErrValidation)
	_, err = c.AddVirtualKeys(ctx, 1, EmailRecipient("A", "a@example.com"), EmailRecipient("", "b@example.com"))
	restTestErrIs(t, err, ErrValidation)
	_, err = c.AddVirtualKeys(ctx, 0, EmailRecipient("A", "a@example.com"))
	restTestErrIs(t, err, ErrValidation)
	restTestErrIs(t, c.RevokeVirtualKey(ctx, 1, 0), ErrValidation)
	if n := len(reqs()); n != 0 {
		t.Errorf("%d requests sent", n)
	}
}

func TestRESTAddVirtualKeysNotRetried(t *testing.T) {
	srv, reqs := restTestServer(t, func(restTestReq) (int, []byte) { return http.StatusBadGateway, nil })
	c, _ := newTestClient(t, srv, nil)
	_, err := c.AddVirtualKeys(context.Background(), 1, EmailRecipient("A", "a@example.com"))
	restTestErrIs(t, err, ErrServer)
	if n := len(reqs()); n != 1 {
		t.Errorf("requests = %d, want 1", n)
	}
}

func TestRESTRevokeVirtualKey(t *testing.T) {
	srv, reqs := restTestServer(t, func(restTestReq) (int, []byte) { return http.StatusNoContent, nil })
	c, _ := newTestClient(t, srv, nil)
	if err := c.RevokeVirtualKey(context.Background(), 85303961, 44122212); err != nil {
		t.Fatal(err)
	}
	got := reqs()
	if len(got) != 1 || got[0].Method != http.MethodDelete || got[0].Path != "/v3/keychains/85303961/virtual_keys/44122212" {
		t.Errorf("requests = %+v", got)
	}
}

func TestRESTVirtualKeyPINRedacted(t *testing.T) {
	k := VirtualKey{ID: 1, PIN: "123456"}
	if s := fmt.Sprint(k.PIN); s == "123456" {
		t.Errorf("PIN printed in clear: %s", s)
	}
}
