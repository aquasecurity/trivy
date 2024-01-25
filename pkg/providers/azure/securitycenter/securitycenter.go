package securitycenter

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type SecurityCenter struct {
	Contacts      []Contact
	Subscriptions []SubscriptionPricing
}

type Contact struct {
	Metadata                 defsecTypes.MisconfigMetadata
	EnableAlertNotifications defsecTypes.BoolValue
	Phone                    defsecTypes.StringValue
}

const (
	TierFree     = "Free"
	TierStandard = "Standard"
)

type SubscriptionPricing struct {
	Metadata defsecTypes.MisconfigMetadata
	Tier     defsecTypes.StringValue
}
