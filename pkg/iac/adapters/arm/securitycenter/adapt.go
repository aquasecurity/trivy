package securitycenter

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/securitycenter"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(deployment azure.Deployment) securitycenter.SecurityCenter {
	return securitycenter.SecurityCenter{
		Contacts:      adaptContacts(deployment),
		Subscriptions: adaptSubscriptions(deployment),
	}
}

func adaptContacts(deployment azure.Deployment) []securitycenter.Contact {
	var contacts []securitycenter.Contact
	for _, resource := range deployment.GetResourcesByType("Microsoft.Security/securityContacts") {
		contacts = append(contacts, adaptContact(resource))
	}

	return contacts
}

func adaptContact(resource azure.Resource) securitycenter.Contact {
	alertsToAdminsState := resource.Properties.GetMapValue("notificationsByRole").GetMapValue("state").AsStringValue("", resource.Metadata)
	isEnabledValue := resource.Properties.GetMapValue("isEnabled").AsBoolValue(false, resource.Metadata)

	enableAlertNotifications, minimalSeverity := extractNotificationSettings(resource, isEnabledValue)

	return securitycenter.Contact{
		Metadata:                 resource.Metadata,
		EnableAlertNotifications: enableAlertNotifications,
		EnableAlertsToAdmins:     iacTypes.Bool(alertsToAdminsState.EqualTo("On"), resource.Metadata),
		Email:                    resource.Properties.GetMapValue("emails").AsStringValue("", resource.Metadata),
		Phone:                    resource.Properties.GetMapValue("phone").AsStringValue("", resource.Metadata),
		IsEnabled:                isEnabledValue,
		MinimalSeverity:          minimalSeverity,
	}
}

func extractNotificationSettings(resource azure.Resource, isEnabled iacTypes.BoolValue) (iacTypes.BoolValue, iacTypes.StringValue) {
	notificationsSources := resource.Properties.GetMapValue("notificationsSources")
	if !notificationsSources.IsNull() {
		return extractFromNotificationsSources(notificationsSources, isEnabled, resource)
	}

	enableAlertNotifications := resource.Properties.GetMapValue("alertNotifications").AsBoolValue(false, resource.Metadata)
	minimalSeverity := iacTypes.StringDefault("", resource.Metadata)
	return enableAlertNotifications, minimalSeverity
}

func extractFromNotificationsSources(notificationsSources azure.Value, isEnabled iacTypes.BoolValue, resource azure.Resource) (iacTypes.BoolValue, iacTypes.StringValue) {
	minimalSeverity := iacTypes.StringDefault("", resource.Metadata)

	for _, source := range notificationsSources.AsList() {
		sourceMap := source.AsMap()
		if sourceMap == nil {
			continue
		}

		sourceType, hasSourceType := sourceMap["sourceType"]
		if !hasSourceType || !sourceType.AsStringValue("", resource.Metadata).EqualTo("Alert") {
			continue
		}

		if minimalSeverityVal, hasMinimalSeverity := sourceMap["minimalSeverity"]; hasMinimalSeverity {
			minimalSeverity = minimalSeverityVal.AsStringValue("", resource.Metadata)
		}
		break
	}

	enableAlertNotifications := iacTypes.Bool(isEnabled.IsTrue() && !minimalSeverity.IsEmpty(), resource.Metadata)
	return enableAlertNotifications, minimalSeverity
}

func adaptSubscriptions(deployment azure.Deployment) []securitycenter.SubscriptionPricing {
	var subscriptions []securitycenter.SubscriptionPricing
	for _, resource := range deployment.GetResourcesByType("Microsoft.Security/pricings") {
		subscriptions = append(subscriptions, adaptSubscription(resource))
	}
	return subscriptions
}

func adaptSubscription(resource azure.Resource) securitycenter.SubscriptionPricing {
	return securitycenter.SubscriptionPricing{
		Metadata: resource.Metadata,
		Tier:     resource.Properties.GetMapValue("pricingTier").AsStringValue("Free", resource.Metadata),
	}
}
