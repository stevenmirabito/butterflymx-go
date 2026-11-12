package butterflymx_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/stevenmirabito/butterflymx-go"
	"github.com/stevenmirabito/butterflymx-go/butterflymxtest"
)

// exampleClient returns a client for an in-memory fake ButterflyMX, so that
// the examples run without a network or an account. A real program builds the
// client from an [auth.Authenticator] instead:
//
//	c, err := butterflymx.New(butterflymx.Options{Auth: authenticator})
//
// and uses the production environment, which is the default.
func exampleClient() (*butterflymx.Client, func()) {
	srv := butterflymxtest.NewServer()
	c, err := butterflymx.New(butterflymx.Options{
		Environment: butterflymx.LocalEnvironment(srv.URL()),
		Auth:        butterflymx.StaticAPIToken(srv.IssueAPIToken()),
	})
	if err != nil {
		log.Fatal(err)
	}
	return c, srv.Close
}

// The full guest-pass flow: find the tenant, pick the doors that can be shared,
// create a pass for a guest, and revoke it again.
func Example() {
	c, closeFake := exampleClient()
	defer closeFake()
	ctx := context.Background()

	tenants, err := c.Tenants(ctx)
	if err != nil {
		log.Fatal(err)
	}
	tenant := tenants[0]
	fmt.Printf("%s, unit %s (guest passes allowed: %t)\n", tenant.Building.Name, tenant.Unit.Label, tenant.CanCreateGuestPasses())

	// Only some doors can be part of a guest pass.
	doors, err := c.AccessPoints(ctx, tenant.ID)
	if err != nil {
		log.Fatal(err)
	}
	var ids []butterflymx.GlobalID
	for _, d := range doors {
		if d.SupportsVirtualKeys() {
			ids = append(ids, d.ID)
			fmt.Println("door:", d.Name)
		}
	}

	// A one-off visit tomorrow evening. ButterflyMX emails the guest a link
	// with the PIN and a QR code.
	start := time.Now().Add(24 * time.Hour).Truncate(time.Hour)
	pass, err := c.CreateKeychain(ctx, butterflymx.CreateKeychainParams{
		TenantID:       tenant.ID,
		AccessPointIDs: ids[:1],
		Name:           "Dinner",
		Schedule:       butterflymx.CustomSchedule{StartsAt: start, EndsAt: start.Add(6 * time.Hour)},
		Recipients:     []butterflymx.Recipient{butterflymx.EmailRecipient("Alex Guest", "alex@example.org")},
	})
	if err != nil {
		log.Fatal(err)
	}
	key := pass.VirtualKeys[0]
	fmt.Printf("created %s pass %q for %s (PIN: %t, QR code: %t, instructions: %t)\n",
		pass.Kind, pass.Name, key.Name, key.PIN.Valid(), key.QRCodeURL != "", key.InstructionsURL != "")

	// Revoke it once the visit is cancelled.
	if err := c.DeleteKeychain(ctx, pass.ID); err != nil {
		log.Fatal(err)
	}
	_, err = c.Keychain(ctx, pass.ID)
	fmt.Println("pass gone:", err != nil)

	// Output:
	// Example Tower, unit 4B (guest passes allowed: true)
	// door: Bike Room
	// door: Garage Gate
	// door: Stairwell Door
	// door: Main Entrance
	// door: Side Door
	// door: Front Door
	// created custom pass "Dinner" for Alex Guest (PIN: true, QR code: true, instructions: true)
	// pass gone: true
}

// A recurring pass for a regular visitor, delivered by SMS: weekdays between
// two dates, in the building's local time.
func ExampleClient_CreateKeychain_recurring() {
	c, closeFake := exampleClient()
	defer closeFake()
	ctx := context.Background()

	tenants, err := c.Tenants(ctx)
	if err != nil {
		log.Fatal(err)
	}
	tenant := tenants[0]
	doors, err := c.AccessPoints(ctx, tenant.ID)
	if err != nil {
		log.Fatal(err)
	}
	var door butterflymx.GlobalID
	for _, d := range doors {
		if d.SupportsVirtualKeys() {
			door = d.ID
			break
		}
	}

	today := butterflymx.DateOf(time.Now())
	pass, err := c.CreateKeychain(ctx, butterflymx.CreateKeychainParams{
		TenantID:       tenant.ID,
		AccessPointIDs: []butterflymx.GlobalID{door},
		Name:           "Dog walker",
		Schedule: butterflymx.RecurringSchedule{
			Weekdays:  []butterflymx.Weekday{butterflymx.Monday, butterflymx.Wednesday, butterflymx.Friday},
			From:      butterflymx.TimeOfDay{Hour: 9},
			To:        butterflymx.TimeOfDay{Hour: 17},
			StartDate: today,
			EndDate:   today.AddDays(90),
		},
		// Phone numbers are normalized to E.164.
		Recipients: []butterflymx.Recipient{butterflymx.SMSRecipient("Sam Walker", "(555) 555-0142")},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(pass.Kind, pass.Weekdays, pass.TimeFrom, "-", pass.TimeTo)
	fmt.Println("texted:", pass.VirtualKeys[0].SMSNumber)

	// Output:
	// recurring [mon wed fri] 09:00 - 17:00
	// texted: +15555550142
}

// A delivery pass is a one-time key without a recipient: show its PIN or QR
// code to the courier yourself.
func ExampleClient_CreateDeliveryPass() {
	c, closeFake := exampleClient()
	defer closeFake()
	ctx := context.Background()

	tenants, err := c.Tenants(ctx)
	if err != nil {
		log.Fatal(err)
	}

	pass, err := c.CreateDeliveryPass(ctx, butterflymx.DeliveryPassParams{
		TenantID: tenants[0].ID,
		Name:     "Groceries",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(pass.Kind, pass.Name, "PIN:", pass.VirtualKeys[0].PIN.Valid())

	// Rename it and give it two more days.
	pass, err = c.UpdateDeliveryPass(ctx, pass.ID, butterflymx.DeliveryPassUpdate{Name: new("Takeout")})
	if err != nil {
		log.Fatal(err)
	}
	if pass, err = c.ExtendDeliveryPass(ctx, pass.ID, 48*time.Hour); err != nil {
		log.Fatal(err)
	}
	fmt.Println("now called", pass.Name)

	if err := c.DeleteKeychain(ctx, pass.ID); err != nil {
		log.Fatal(err)
	}

	// Output:
	// delivery_pass Groceries PIN: true
	// now called Takeout
}
