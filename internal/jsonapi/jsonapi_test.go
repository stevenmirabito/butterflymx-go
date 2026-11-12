package jsonapi

import (
	"encoding/json/jsontext"
	"testing"
)

const keychainDoc = `{
  "data": {"id":"100","type":"keychains","weird":1,
    "attributes":{"name":"Guest","kind":"custom","future_field":true},
    "relationships":{
      "tenant":{"data":{"type":"tenants","id":"8000001"}},
      "virtual_keys":{"data":[{"type":"virtual_keys","id":"200"}]},
      "devices":{"data":[{"type":"panels","id":"200"},{"type":"cloud_keyz_controllers","id":"200"},{"type":"panels","id":"999"}]},
      "nothing":{"data":null},
      "empty":{"data":[]},
      "linksonly":{"links":{"self":"x"}}
    }},
  "included":[
    {"id":"200","type":"virtual_keys","attributes":{"pin":"1234"}},
    {"id":"200","type":"panels","attributes":{"name":"Front"}},
    {"id":"200","type":"cloud_keyz_controllers","attributes":{"name":"Garage"}}
  ],
  "links":{"self":"https://x/v3/keychains/100"},
  "jsonapi":{"version":"1.0"}
}`

func TestIndexCollision(t *testing.T) {
	d, err := Decode([]byte(keychainDoc))
	if err != nil {
		t.Fatal(err)
	}
	kc, err := d.One()
	if err != nil {
		t.Fatal(err)
	}
	var attrs struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
	}
	if err := kc.DecodeAttributes(&attrs); err != nil || attrs.Name != "Guest" || attrs.Kind != "custom" {
		t.Fatalf("attrs %+v %v", attrs, err)
	}
	idx := d.Index()
	devs, missing, err := idx.Resolve(kc.Relationships["devices"])
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 2 || devs[0].Type != "panels" || devs[1].Type != "cloud_keyz_controllers" {
		t.Fatalf("devs %+v", devs)
	}
	var pa struct {
		Name string `json:"name"`
	}
	_ = devs[0].DecodeAttributes(&pa)
	if pa.Name != "Front" {
		t.Fatalf("collision resolved wrong: %q", pa.Name)
	}
	if len(missing) != 1 || missing[0] != (Identifier{"panels", "999"}) {
		t.Fatalf("missing %+v", missing)
	}
	vk, ok := idx.Get(Identifier{"virtual_keys", "200"})
	if !ok || string(vk.Attributes) != `{"pin":"1234"}` {
		t.Fatalf("vk %+v", vk)
	}
	if _, ok := idx.Get(Identifier{"tenants", "8000001"}); ok {
		t.Fatal("unexpected")
	}
	if _, ok := idx.Get(kc.Identifier); !ok {
		t.Fatal("primary not indexed")
	}
}

func TestRelationshipShapes(t *testing.T) {
	d, _ := Decode([]byte(keychainDoc))
	kc, _ := d.One()
	for _, name := range []string{"nothing", "linksonly", "absent"} {
		r := kc.Relationships[name]
		if one, err := r.One(); err != nil || one != nil {
			t.Errorf("%s One: %v %v", name, one, err)
		}
		if many, err := r.Many(); err != nil || len(many) != 0 {
			t.Errorf("%s Many: %v %v", name, many, err)
		}
	}
	if many, err := kc.Relationships["empty"].Many(); err != nil || len(many) != 0 {
		t.Errorf("empty: %v %v", many, err)
	}
	one, err := kc.Relationships["tenant"].One()
	if err != nil || one == nil || *one != (Identifier{"tenants", "8000001"}) {
		t.Errorf("tenant %v %v", one, err)
	}
	if _, err := kc.Relationships["devices"].One(); err == nil {
		t.Error("One on array should fail")
	}
	// missing included is a soft miss, not an error
	d2, _ := Decode([]byte(`{"data":{"id":"1","type":"keychains","relationships":{"v":{"data":[{"type":"virtual_keys","id":"5"}]}}}}`))
	r, _ := d2.One()
	got, miss, err := d2.Index().Resolve(r.Relationships["v"])
	if err != nil || len(got) != 0 || len(miss) != 1 {
		t.Errorf("soft miss: %v %v %v", got, miss, err)
	}
}

func TestListPagination(t *testing.T) {
	p1 := `{"data":[{"id":"1","type":"keychains"},{"id":"2","type":"keychains"}],
	 "links":{"self":"a?page[number]=1","first":"a?page[number]=1","prev":null,"next":"a?page[number]=2","last":"a?page[number]=2"}}`
	p2 := `{"data":[{"id":"3","type":"keychains"}],
	 "links":{"self":"a?page[number]=2","first":"a?page[number]=1","prev":"a?page[number]=1","next":null,"last":"a?page[number]=2"}}`
	d1, err := Decode([]byte(p1))
	if err != nil {
		t.Fatal(err)
	}
	rs, err := d1.Many()
	if err != nil || len(rs) != 2 || rs[1].ID != "2" {
		t.Fatalf("%v %v", rs, err)
	}
	if !HasNext(d1.Links) || d1.Links.Prev != "" || d1.Links.Next != "a?page[number]=2" {
		t.Fatalf("links %+v", d1.Links)
	}
	d2, _ := Decode([]byte(p2))
	if HasNext(d2.Links) || d2.Links.Prev == "" {
		t.Fatalf("links %+v", d2.Links)
	}
	if _, err := d1.One(); err == nil {
		t.Error("One on array")
	}
	if _, err := d2.Many(); err != nil {
		t.Error(err)
	}
	empty, _ := Decode([]byte(`{"data":[],"links":{"next":null}}`))
	if rs, err := empty.Many(); err != nil || len(rs) != 0 {
		t.Error(rs, err)
	}
}

func TestCreateResponse201(t *testing.T) {
	body := `{"data":{"id":"300","type":"keychains","attributes":{"kind":"custom","starts_at":"2026-11-12T05:00:00Z","start_date":null},
	 "relationships":{"virtual_keys":{"data":[{"type":"virtual_keys","id":"301"}]},"tenant":{"data":{"type":"tenants","id":"8000001"}}}},
	 "included":[{"id":"301","type":"virtual_keys","attributes":{"pin":"0000","qr_code_image_url":"https://x/q.png","email":"a@example.com","sms_number":null}}]}`
	d, err := Decode([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	kc, _ := d.One()
	vks, miss, err := d.Index().Resolve(kc.Relationships["virtual_keys"])
	if err != nil || len(vks) != 1 || len(miss) != 0 {
		t.Fatal(vks, miss, err)
	}
	var a struct {
		Pin      string  `json:"pin"`
		SMS      *string `json:"sms_number"`
		Email    *string `json:"email"`
		Greeting string  `json:"greeting"`
	}
	if err := vks[0].DecodeAttributes(&a); err != nil || a.Pin != "0000" || a.SMS != nil || a.Email == nil {
		t.Fatalf("%+v %v", a, err)
	}
}

func TestErrors(t *testing.T) {
	body := `{"errors":[
	 {"status":"400","code":"invalid","title":"Invalid","detail":"ends_at must be after starts_at","source":{"pointer":"/data/attributes/ends_at"},"extra":1},
	 {"status":404,"title":"Not found","source":{"parameter":"include"}},
	 {"title":"bare","meta":{"x":1}}]}`
	d, err := Decode([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Errors) != 3 {
		t.Fatalf("%+v", d.Errors)
	}
	e := d.Errors[0]
	if e.Status != "400" || e.Code != "invalid" || e.Source == nil || e.Source.Pointer != "/data/attributes/ends_at" {
		t.Errorf("%+v", e)
	}
	if e := d.Errors[1]; e.Status != "404" || e.Source == nil || e.Source.Parameter != "include" {
		t.Errorf("%+v", e)
	}
	if e := d.Errors[2]; e.Source != nil || e.Title != "bare" {
		t.Errorf("%+v", e)
	}
	if d.Errors[0].Error() == "" {
		t.Error("Error()")
	}
	if _, err := d.One(); err == nil {
		t.Error("One without data")
	}
}

func TestDecodeGarbage(t *testing.T) {
	if _, err := Decode([]byte(`not json`)); err == nil {
		t.Error("want error")
	}
	if _, err := Decode(nil); err == nil {
		t.Error("want error on empty")
	}
	d, err := Decode([]byte(`{"links":{"self":{"href":"h"}}}`))
	if err != nil || d.Links.Self != "h" {
		t.Errorf("%v %+v", err, d)
	}
}

func canon(t *testing.T, b []byte) string {
	t.Helper()
	v := jsontext.Value(append([]byte(nil), b...))
	if err := v.Canonicalize(); err != nil {
		t.Fatalf("canonicalize %s: %v", b, err)
	}
	return string(v)
}

func assertJSON(t *testing.T, got []byte, want string) {
	t.Helper()
	if g, w := canon(t, got), canon(t, []byte(want)); g != w {
		t.Errorf("mismatch\n got: %s\nwant: %s", g, w)
	}
}

type customAttrs struct {
	Kind            string      `json:"kind"`
	Name            string      `json:"name"`
	StartsAt        string      `json:"starts_at"`
	EndsAt          string      `json:"ends_at"`
	AllowUnitAccess bool        `json:"allow_unit_access"`
	Recipients      []recipient `json:"recipients"`
	StartDate       *string     `json:"start_date"`
	EndDate         *string     `json:"end_date"`
	TimeFrom        *string     `json:"time_from"`
	TimeTo          *string     `json:"time_to"`
	Weekdays        []string    `json:"weekdays"`
}

type recipient struct {
	Name      string `json:"name"`
	DeliverTo string `json:"deliver_to"`
}

func TestMarshalCreateCustom(t *testing.T) {
	b, err := Marshal(ResourceObject{
		Type: "keychains",
		Attributes: customAttrs{
			Kind: "custom", Name: "Guest", StartsAt: "2026-11-12T05:00:00Z", EndsAt: "2026-11-12T06:00:00Z",
			Recipients: []recipient{{"Alex Guest", "alex@example.com"}},
		},
		Relationships: map[string]RelationshipObject{
			"tenant":        ToOne("tenants", "8000001"),
			"access_points": ToMany("access_points", "70001", "70002"),
			"virtual_keys":  ToMany("virtual_keys"),
			"devices":       ToMany("devices"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, b, `{"data":{"type":"keychains",
	 "attributes":{"kind":"custom","name":"Guest","starts_at":"2026-11-12T05:00:00Z","ends_at":"2026-11-12T06:00:00Z",
	   "allow_unit_access":false,"recipients":[{"name":"Alex Guest","deliver_to":"alex@example.com"}],
	   "start_date":null,"end_date":null,"time_from":null,"time_to":null,"weekdays":[]},
	 "relationships":{
	   "tenant":{"data":{"type":"tenants","id":"8000001"}},
	   "access_points":{"data":[{"type":"access_points","id":"70001"},{"type":"access_points","id":"70002"}]},
	   "virtual_keys":{"data":[]},"devices":{"data":[]}}}}`)
}

func TestMarshalPatch(t *testing.T) {
	end := "2027-01-10T21:12:03-0800"
	b, err := Marshal(ResourceObject{
		Type: "keychains", ID: "100",
		Attributes: customAttrs{Kind: "delivery_pass", Name: "Amazon", EndsAt: end, Weekdays: []string{}},
		Relationships: map[string]RelationshipObject{
			"tenant":       ToOneNull("tenants"),
			"virtual_keys": ToMany("virtual_keys", "52000001"),
			"nothing":      Null(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, b, `{"data":{"type":"keychains","id":"100",
	 "attributes":{"kind":"delivery_pass","name":"Amazon","starts_at":"","ends_at":"2027-01-10T21:12:03-0800",
	   "allow_unit_access":false,"recipients":[],"start_date":null,"end_date":null,"time_from":null,"time_to":null,"weekdays":[]},
	 "relationships":{
	   "tenant":{"data":{"type":"tenants","id":null}},
	   "virtual_keys":{"data":[{"type":"virtual_keys","id":"52000001"}]},
	   "nothing":{"data":null}}}}`)
}

func TestMarshalNullAttributesAndMinimal(t *testing.T) {
	b, err := Marshal(ResourceObject{Type: "keychains", Attributes: map[string]any{"start_date": nil, "name": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, b, `{"data":{"type":"keychains","attributes":{"start_date":null,"name":"x"}}}`)

	b, err = Marshal(ResourceObject{Type: "keychains"})
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, b, `{"data":{"type":"keychains"}}`)

	// zero RelationshipObject is data:null
	b, _ = Marshal(ResourceObject{Type: "k", Relationships: map[string]RelationshipObject{"a": {}}})
	assertJSON(t, b, `{"data":{"type":"k","relationships":{"a":{"data":null}}}}`)
}
