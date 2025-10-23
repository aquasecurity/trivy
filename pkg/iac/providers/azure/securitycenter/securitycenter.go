package securitycenter

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type SecurityCenter struct {
	Contacts      []Contact
	Subscriptions []SubscriptionPricing
}

type Contact struct {
	Metadata             iacTypes.Metadata
	IsEnabled            iacTypes.BoolValue
	EnableAlertsToAdmins iacTypes.BoolValue
	Email                iacTypes.StringValue
	Phone                iacTypes.StringValue
	NotificationsSources []NotificationSource
}

type NotificationSource struct {
	SourceType      iacTypes.StringValue
	MinimalSeverity iacTypes.StringValue
}

const (
	TierFree     = "Free"
	TierStandard = "Standard"
)

type SubscriptionPricing struct {
	Metadata iacTypes.Metadata
	Tier     iacTypes.StringValue
}
