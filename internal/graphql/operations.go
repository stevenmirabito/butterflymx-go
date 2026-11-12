package graphql

import (
	_ "embed"
)

// Operation is a named GraphQL query document as sent by the official app.
type Operation struct {
	Name     string
	Document string
}

//go:embed ops/CurrentUser.graphql
var currentUserDoc string

//go:embed ops/Tenants.graphql
var tenantsDoc string

//go:embed ops/Tenant.graphql
var tenantDoc string

//go:embed ops/TenantAccessPoints.graphql
var tenantAccessPointsDoc string

//go:embed ops/TenantDoorReleases.graphql
var tenantDoorReleasesDoc string

//go:embed ops/TenantCalls.graphql
var tenantCallsDoc string

//go:embed ops/TenantMessages.graphql
var tenantMessagesDoc string

//go:embed ops/TenantRemoteLocks.graphql
var tenantRemoteLocksDoc string

//go:embed ops/TenantSmartLocks.graphql
var tenantSmartLocksDoc string

//go:embed ops/TenantLPRSettings.graphql
var tenantLPRSettingsDoc string

//go:embed ops/GetBLECredentials.graphql
var getBLECredentialsDoc string

// The operations the official iOS app sends.
var (
	CurrentUser        = Operation{"CurrentUser", currentUserDoc}
	Tenants            = Operation{"Tenants", tenantsDoc}
	Tenant             = Operation{"Tenant", tenantDoc}
	TenantAccessPoints = Operation{"TenantAccessPoints", tenantAccessPointsDoc}
	TenantDoorReleases = Operation{"TenantDoorReleases", tenantDoorReleasesDoc}
	TenantCalls        = Operation{"TenantCalls", tenantCallsDoc}
	TenantMessages     = Operation{"TenantMessages", tenantMessagesDoc}
	TenantRemoteLocks  = Operation{"TenantRemoteLocks", tenantRemoteLocksDoc}
	TenantSmartLocks   = Operation{"TenantSmartLocks", tenantSmartLocksDoc}
	TenantLPRSettings  = Operation{"TenantLPRSettings", tenantLPRSettingsDoc}
	GetBLECredentials  = Operation{"GetBLECredentials", getBLECredentialsDoc}
)

func allOperations() []Operation {
	return []Operation{CurrentUser, Tenants, Tenant, TenantAccessPoints, TenantDoorReleases,
		TenantCalls, TenantMessages, TenantRemoteLocks, TenantSmartLocks, TenantLPRSettings, GetBLECredentials}
}

// Extensions returns the extensions object the app (Apollo iOS) sends.
func Extensions() map[string]any {
	return map[string]any{
		"clientLibrary": map[string]any{"name": "apollo-ios", "version": "2.4.0"},
	}
}
