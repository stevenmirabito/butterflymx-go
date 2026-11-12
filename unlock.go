package butterflymx

import (
	"context"
	"fmt"
	"net/http"
)

// Unlock asks the unlock service to open the access point for the tenant, as
// the mobile app does (source "mobile_app"), and returns the service's
// request ID. The door opens asynchronously; a nil error means the request
// was accepted, not that the door is open.
//
// Unlock is never retried automatically, because a replayed request could
// open the door twice. It returns an error wrapping ErrNotSupported when the
// environment has no unlock service URL, and an error wrapping ErrIDType
// (before any request) if tenantID is not a tenant ID or accessPointID is not
// an access point ID.
func (c *Client) Unlock(ctx context.Context, tenantID, accessPointID GlobalID) (requestID string, err error) {
	const op = "Unlock"
	if err := gqlCheckID(op, tenantID, TypeTenant); err != nil {
		return "", err
	}
	if err := gqlCheckID(op, accessPointID, TypeAccessPoint); err != nil {
		return "", err
	}
	in := struct {
		AccessPointID string `json:"accessPointId"`
		TenantID      string `json:"tenantId"`
		Source        string `json:"source"`
	}{accessPointID.String(), tenantID.String(), "mobile_app"}
	var out struct {
		RequestID string `json:"requestId"`
	}
	if err := c.doJSON(ctx, op, http.MethodPost, unlockBase, "/v1/access-point", in, &out); err != nil {
		return "", err
	}
	if out.RequestID == "" {
		return "", &Error{Op: op, Method: http.MethodPost, URL: "/v1/access-point",
			Err: fmt.Errorf("response has no requestId")}
	}
	return out.RequestID, nil
}
