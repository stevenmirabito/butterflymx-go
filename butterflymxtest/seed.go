package butterflymxtest

import (
	"crypto/rand"
	"fmt"
	"slices"
	"time"
)

type seedPass struct {
	kcID, vkID, name, vkName, pin string
	guest                         int
	startsAgo, endsIn             time.Duration
}

func (s *Server) seedPasses(w *world) {
	now := s.now()
	day := 24 * time.Hour
	for _, id := range []string{
		"15387693", "99130956", "95370988", "38659984", "95138079", "38703205", "68513236", "35327219",
		"48184743", "85404824", "88220723", "69527006",
	} {
		w.used[id] = true
	}

	vkAPs := func() []string {
		var ids []string
		for _, a := range w.aps {
			if a.hasCap("VIRTUAL_KEYS") {
				ids = append(ids, a.id)
			}
		}
		return ids
	}

	active := []seedPass{
		{"15387693", "99130956", "Guest One", "Guest One", "246801", 1, 14 * day, 350 * day},
		{"95370988", "38659984", "Guest Two", "Guest Two", "135790", 2, 25 * day, 340 * day},
		{"95138079", "38703205", "Guest Three", "Guest Three", "098765", 3, 28 * day, 335 * day},
		{"68513236", "35327219", "Guest Pass One", "Guest Four", "314159", 4, 90 * day, 270 * day},
		{"48184743", "85404824", "Guest Five", "Guest Five", "271828", 5, 230 * day, 130 * day},
	}
	for _, p := range active {
		starts := now.Add(-p.startsAgo).Truncate(time.Minute)
		k := &keychain{
			id: p.kcID, name: p.name, kind: "custom", tenantID: tenantID,
			startsAt: starts, endsAt: now.Add(p.endsIn).Truncate(time.Minute),
			apIDs: []string{"28821"},
		}
		k.fromInstants(w.loc)
		vk := s.mkVirtualKey(p.vkID, p.pin, p.vkName, "", fmt.Sprintf("+15555550%03d", 100+p.guest))
		vk.sentAt = starts.Add(time.Minute)
		k.vks = append(k.vks, vk)
		w.keychains = append(w.keychains, k)
		w.seed.ActiveKeychainIDs = append(w.seed.ActiveKeychainIDs, k.id)
	}
	// A guest key with a few door releases (the "Guest Four" key).
	if _, vk := w.findVK("35327219"); vk != nil {
		ap := w.ap("28821")
		for i := 0; i < 3; i++ {
			s.newRelease(now.Add(-time.Duration(20+i*9)*24*time.Hour), ap, "VIRTUAL_KEY_PIN", "virtual_key_pin", "VISITOR", "visitor", vk.id, vk.name)
		}
	}

	dpStart := now.Add(-10 * day)
	dp := &keychain{
		id: "88220723", name: "Delivery Pass", kind: "delivery_pass", tenantID: tenantID,
		startsAt: dpStart, endsAt: dpStart.Add(30 * day), apIDs: vkAPs(),
	}
	dp.fromInstants(w.loc)
	dp.vks = append(dp.vks, s.mkVirtualKey("69527006", "024680", "Delivery Pass", "", ""))
	w.keychains = append(w.keychains, dp)
	w.seed.DeliveryPassID = dp.id
	w.seed.ActiveKeychainIDs = append(w.seed.ActiveKeychainIDs, dp.id)

	// Expired passes: more than one page at the default page size.
	fixtureIDs := []string{
		"61887457", "83924680", "88393470", "12389765", "93569808", "57056320", "26972649", "88501968", "89626913", "55228549",
		"48021700", "61729123", "19978793", "87189311", "29096468", "27705675", "35220453", "89691680", "55489874", "25021355",
	}
	deliveryIdx := []int{1, 2, 3, 7, 8, 10, 11, 12, 15, 16, 21}
	for i := 0; i < 24; i++ {
		id := ""
		if i < len(fixtureIDs) {
			id = fixtureIDs[i]
			w.used[id] = true
		} else {
			id = s.randID(8, w.used)
		}
		ends := now.Add(-time.Duration(3+9*i) * day).Truncate(time.Minute)
		k := &keychain{id: id, tenantID: tenantID, endsAt: ends}
		if slices.Contains(deliveryIdx, i) {
			k.kind, k.name, k.apIDs = "delivery_pass", "Delivery Pass", vkAPs()
			k.startsAt = ends.Add(-30 * day)
			k.fromInstants(w.loc)
			vk := s.mkVirtualKey(s.randID(8, w.used), s.newPIN(), "Delivery Pass", "", "")
			vk.usedAt = k.startsAt.Add(2 * day)
			k.endsAt = vk.usedAt.Add(15 * time.Minute)
			k.fromInstants(w.loc)
			k.vks = append(k.vks, vk)
			w.keychains = append(w.keychains, k)
			s.newRelease(vk.usedAt, w.ap("28821"), "VIRTUAL_KEY_PIN", "delivery_pass", "DELIVERY", "delivery", vk.id, vk.name)
		} else {
			k.kind, k.name, k.apIDs = "custom", fmt.Sprintf("Guest Pass %d", i+1), []string{"28821"}
			k.startsAt = ends.Add(-5 * time.Hour)
			k.fromInstants(w.loc)
			guest := fmt.Sprintf("Guest %d", i+6)
			sms, email := fmt.Sprintf("+15555550%03d", 110+i), ""
			if i%3 == 0 {
				sms, email = "", fmt.Sprintf("guest%d@example.com", i+6)
			}
			vk := s.mkVirtualKey(s.randID(8, w.used), s.newPIN(), guest, email, sms)
			vk.sentAt = k.startsAt.Add(-time.Hour)
			k.vks = append(k.vks, vk)
			w.keychains = append(w.keychains, k)
			if i%2 == 0 {
				for j := 0; j < 1+i%3; j++ {
					s.newRelease(k.startsAt.Add(time.Duration(30+j*40)*time.Minute), w.ap("28821"), "VIRTUAL_KEY_PIN", "virtual_key_pin", "VISITOR", "visitor", vk.id, vk.name)
				}
			}
		}
		w.seed.ExpiredKeychainIDs = append(w.seed.ExpiredKeychainIDs, id)
	}
}

func (s *Server) seedHistory(w *world) {
	now := s.now()
	type hist struct {
		ap, method string
	}
	cycle := []hist{
		{"12921", "SWIPE_TO_OPEN"}, {"28821", "SWIPE_TO_OPEN"}, {"28821", "SWIPE_TO_OPEN"}, {"61152", "RFID"},
		{"12921", "RFID"}, {"28821", "MOBILE_CALL"}, {"28821", "MOBILE_CALL"}, {"28821", "SWIPE_TO_OPEN"},
	}
	for i := 0; i < 25; i++ {
		h := cycle[i%len(cycle)]
		s.newRelease(now.Add(-time.Duration(1+i*31)*time.Hour), w.ap(h.ap), h.method, "", "VISITOR", "visitor", "", "")
	}
	statuses := []string{"OPENED_DOOR", "OPENED_DOOR", "CANCELED", "CONNECTING_SIP", "CONNECTED", "TIMEOUT_ONLINE_SIGNAL"}
	for i := 0; i < 25; i++ {
		notif := "VISITOR"
		if i%9 == 2 {
			notif = "DELIVERY"
		}
		w.calls = append(w.calls, &callRec{
			num: s.randID(9, w.used), guid: s.uuid(), at: now.Add(-time.Duration(2+i*47) * time.Hour),
			imageURL: w.newImageURL(), notif: notif, status: statuses[i%len(statuses)],
		})
	}
	w.messages = []*messageRec{
		{num: s.randID(8, w.used), title: "Water shutoff", body: "Water will be off on Tuesday from 9am to noon.",
			logoURL: "https://example.com/logo.png", imageURL: "https://example.com/images/message.jpg", at: now.Add(-48 * time.Hour)},
		{num: s.randID(8, w.used), title: "Package room", body: "Packages are now held in the package room.",
			logoURL: "https://example.com/logo.png", imageURL: "https://example.com/images/message.jpg", at: now.Add(-9 * 24 * time.Hour)},
	}
}

// uuid returns a random version 4 UUID.
func (s *Server) uuid() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
