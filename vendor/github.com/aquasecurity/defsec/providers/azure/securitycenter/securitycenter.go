package securitycenter

import "github.com/aquasecurity/defsec/parsers/types"

type SecurityCenter struct {
	types.Metadata
	Contacts      []Contact
	Subscriptions []SubscriptionPricing
}

type Contact struct {
	types.Metadata
	EnableAlertNotifications types.BoolValue
	Phone                    types.StringValue
}

const (
	TierFree     = "Free"
	TierStandard = "Standard"
)

type SubscriptionPricing struct {
	types.Metadata
	Tier types.StringValue
}
