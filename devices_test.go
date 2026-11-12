package butterflymx

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// restTestForm converts a fixture's form body (a JSON object, with arrays for
// repeated keys) to url.Values.
func restTestForm(t testing.TB, v any) url.Values {
	t.Helper()
	out := url.Values{}
	for k, val := range v.(map[string]any) {
		switch x := val.(type) {
		case string:
			out.Set(k, x)
		case []any:
			for _, e := range x {
				out.Add(k, e.(string))
			}
		default:
			t.Fatalf("form field %s: unexpected %T", k, val)
		}
	}
	return out
}

func TestRESTRegisterPushDeviceShape(t *testing.T) {
	srv, reqs := restTestServer(t, func(restTestReq) (int, []byte) {
		return http.StatusOK, restTestRespBody(t, "post-mobile-users-devices-200")
	})
	c, _ := newTestClient(t, srv, nil)
	d, err := c.RegisterPushDevice(context.Background(), PushDeviceParams{
		ClientVersion: "1001.125.2", Description: "iPhone18,1", Token: "FAKE_PUSH_TOKEN", VoIPToken: "FAKE_VOIP_TOKEN",
		Locales: []string{"en-US", "com-US"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := reqs()
	if len(got) != 1 || got[0].Method != http.MethodPost || got[0].Path != "/mobile/v4/users/devices" {
		t.Fatalf("requests = %+v", got)
	}
	if ct := got[0].Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded; charset=utf-8" {
		t.Errorf("content-type = %q", ct)
	}
	form, err := url.ParseQuery(string(got[0].Body))
	if err != nil {
		t.Fatal(err)
	}
	want := restTestForm(t, restTestReqBody(t, "post-mobile-users-devices-200"))
	if form.Encode() != want.Encode() {
		t.Errorf("form = %v\nwant   %v", form, want)
	}

	if d.ID != 65794426 || d.GlobalID != NewGlobalID("prod", TypeUserDeviceApple, 65794426) || d.Client != "iphone" ||
		d.Description != "iPhone18,1" || d.ClientVersion != "1001.125.2" || d.Token != "FAKE_PUSH_TOKEN" ||
		d.VoIPToken != "FAKE_VOIP_TOKEN" || d.Development || d.CallNotificationPushType != "voip" ||
		len(d.Locales) != 1 || d.Locales[0] != "en-US" {
		t.Errorf("device = %#v", d)
	}
}

func TestRESTRegisterPushDeviceDevelopmentFlag(t *testing.T) {
	srv, reqs := restTestServer(t, func(restTestReq) (int, []byte) {
		return http.StatusOK, restTestRespBody(t, "post-mobile-users-devices-200")
	})
	c, _ := newTestClient(t, srv, nil)
	if _, err := c.RegisterPushDevice(context.Background(), PushDeviceParams{Client: "android", Token: "t", Development: true}); err != nil {
		t.Fatal(err)
	}
	form, _ := url.ParseQuery(string(reqs()[0].Body))
	if form.Get("device[development]") != "1" || form.Get("device[client]") != "android" || form.Has("device[voip_token]") || form.Has("device[locales][]") {
		t.Errorf("form = %v", form)
	}
}

func TestRESTTouchAndDeletePushDeviceShape(t *testing.T) {
	srv, reqs := restTestServer(t, func(r restTestReq) (int, []byte) {
		if r.Method == http.MethodDelete {
			return http.StatusNoContent, nil
		}
		return http.StatusOK, restTestRespBody(t, "patch-mobile-users-devices-200")
	})
	c, _ := newTestClient(t, srv, nil)
	d, err := c.TouchPushDevice(context.Background(), 65794426)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.DeletePushDevice(context.Background(), 65794426); err != nil {
		t.Fatal(err)
	}
	got := reqs()
	if len(got) != 2 || got[0].Method != http.MethodPatch || got[0].Path != "/mobile/v4/users/devices/65794426" ||
		got[1].Method != http.MethodDelete || got[1].Path != "/mobile/v4/users/devices/65794426" || len(got[1].Body) != 0 {
		t.Fatalf("requests = %+v", got)
	}
	if string(got[0].Body) != restTestForm(t, restTestReqBody(t, "patch-mobile-users-devices-200")).Encode() {
		t.Errorf("patch body = %q", got[0].Body)
	}
	if d.ID != 65794426 || d.Client != "iphone" {
		t.Errorf("device = %#v", d)
	}
	_, err = c.TouchPushDevice(context.Background(), 0)
	restTestErrIs(t, err, ErrValidation)
	restTestErrIs(t, c.DeletePushDevice(context.Background(), 0), ErrValidation)
}

func TestRESTTouchPushDeviceNoBody(t *testing.T) {
	srv, _ := restTestServer(t, func(restTestReq) (int, []byte) { return http.StatusNoContent, nil })
	c, _ := newTestClient(t, srv, nil)
	d, err := c.TouchPushDevice(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if d.ID != 7 {
		t.Errorf("device = %#v", d)
	}
}

func TestRESTPushDeviceSecretsNotPrinted(t *testing.T) {
	d := PushDevice{ID: 1, Client: "iphone", Token: "SECRET_PUSH", VoIPToken: "SECRET_VOIP"}
	//nolint:staticcheck // Deliberately exercise the %s verb to check secret redaction.
	//lint:ignore S1025 Deliberately exercise the %s verb to check secret redaction.
	for _, s := range []string{fmt.Sprint(d), fmt.Sprintf("%v", d), fmt.Sprintf("%s", d), fmt.Sprintf("%+v", &d)} {
		if strings.Contains(s, "SECRET") {
			t.Errorf("token printed: %s", s)
		}
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("registered", "device", d)
	if out := buf.String(); strings.Contains(out, "SECRET") || !strings.Contains(out, "has_token=true") {
		t.Errorf("log = %s", out)
	}
}

func TestRESTPushDeviceLifecycle(t *testing.T) {
	c, _ := newFakeClient(t)
	ctx := context.Background()
	d, err := c.RegisterPushDevice(ctx, PushDeviceParams{
		ClientVersion: "1001.125.2", Description: "iPhone18,1", Token: "FAKE_PUSH_TOKEN", VoIPToken: "FAKE_VOIP_TOKEN",
		Locales: []string{"en-US"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.ID == 0 || d.GlobalID.Type != TypeUserDeviceApple || d.GlobalID.Num != d.ID || d.Token != "FAKE_PUSH_TOKEN" ||
		d.CallNotificationPushType != "voip" || len(d.Locales) != 1 {
		t.Fatalf("device = %#v", d)
	}
	touched, err := c.TouchPushDevice(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if touched.ID != d.ID || touched.Token != d.Token || touched.Description != "iPhone18,1" {
		t.Errorf("touched = %#v", touched)
	}
	if err := c.DeletePushDevice(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	_, err = c.TouchPushDevice(ctx, d.ID)
	restTestErrIs(t, err, ErrNotFound)
	restTestErrIs(t, c.DeletePushDevice(ctx, d.ID), ErrNotFound)
}
