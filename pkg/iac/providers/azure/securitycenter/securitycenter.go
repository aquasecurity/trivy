package securitycenter

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type SecurityCenter struct {
	Contacts      []Contact
	Subscriptions []SubscriptionPricing
}

type Contact struct {
	Metadata                 defsecTypes.Metadata
	EnableAlertNotifications defsecTypes.BoolValue
	Phone                    defsecTypes.StringValue
}

const (
	TierFree     = "Free"
	TierStandard = "Standard"
)

type SubscriptionPricing struct {
	Metadata defsecTypes.Metadata
	Tier     defsecTypes.StringValue
}
