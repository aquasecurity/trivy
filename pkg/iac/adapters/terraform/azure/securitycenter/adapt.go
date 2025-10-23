package securitycenter

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/securitycenter"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) securitycenter.SecurityCenter {
	return securitycenter.SecurityCenter{
		Contacts:      adaptContacts(modules),
		Subscriptions: adaptSubscriptions(modules),
	}
}

func adaptContacts(modules terraform.Modules) []securitycenter.Contact {
	var contacts []securitycenter.Contact

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_security_center_contact") {
			contacts = append(contacts, adaptContact(resource))
		}
	}
	return contacts
}

func adaptSubscriptions(modules terraform.Modules) []securitycenter.SubscriptionPricing {
	var subscriptions []securitycenter.SubscriptionPricing

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_security_center_subscription_pricing") {
			subscriptions = append(subscriptions, adaptSubscription(resource))
		}
	}
	return subscriptions
}

func adaptContact(resource *terraform.Block) securitycenter.Contact {
	// Handle both old and new schema fields
	isEnabledAttr := resource.GetAttribute("is_enabled")
	isEnabledVal := isEnabledAttr.AsBoolValueOrDefault(false, resource)

	// Fallback to alert_notifications for backward compatibility
	if !isEnabledAttr.IsNil() {
		// New schema - use is_enabled
	} else {
		// Old schema - derive from alert_notifications
		enableAlertNotifAttr := resource.GetAttribute("alert_notifications")
		if !enableAlertNotifAttr.IsNil() {
			isEnabledVal = enableAlertNotifAttr.AsBoolValueOrDefault(false, resource)
		}
	}

	alertsToAdminsAttr := resource.GetAttribute("alerts_to_admins")
	alertsToAdminsVal := alertsToAdminsAttr.AsBoolValueOrDefault(false, resource)

	emailAttr := resource.GetAttribute("email")
	emailVal := emailAttr.AsStringValueOrDefault("", resource)

	phoneAttr := resource.GetAttribute("phone")
	phoneVal := phoneAttr.AsStringValueOrDefault("", resource)

	// Handle notifications_sources if present
	notificationsSources := adaptTerraformNotificationsSources(resource)
	if notificationsSources == nil {
		notificationsSources = []securitycenter.NotificationSource{}
	}

	return securitycenter.Contact{
		Metadata:             resource.GetMetadata(),
		IsEnabled:            isEnabledVal,
		EnableAlertsToAdmins: alertsToAdminsVal,
		Email:                emailVal,
		Phone:                phoneVal,
		NotificationsSources: notificationsSources,
	}
}

func adaptTerraformNotificationsSources(resource *terraform.Block) []securitycenter.NotificationSource {
	var sources []securitycenter.NotificationSource

	notificationsSourcesAttr := resource.GetAttribute("notifications_sources")
	if notificationsSourcesAttr.IsNotNil() && notificationsSourcesAttr.IsIterable() {
		value := notificationsSourcesAttr.Value()
		if value.Type().IsListType() || value.Type().IsTupleType() {
			for _, sourceValue := range value.AsValueSlice() {
				if sourceValue.Type().IsObjectType() || sourceValue.Type().IsMapType() {
					sourceMap := sourceValue.AsValueMap()
					sourceType := ""
					minimalSeverity := ""

					if sourceTypeVal, exists := sourceMap["source_type"]; exists && !sourceTypeVal.IsNull() {
						sourceType = sourceTypeVal.AsString()
					}
					if severityVal, exists := sourceMap["minimal_severity"]; exists && !severityVal.IsNull() {
						minimalSeverity = severityVal.AsString()
					}

					sources = append(sources, securitycenter.NotificationSource{
						SourceType:      iacTypes.String(sourceType, resource.GetMetadata()),
						MinimalSeverity: iacTypes.String(minimalSeverity, resource.GetMetadata()),
					})
				}
			}
		}
	}

	return sources
}

func adaptSubscription(resource *terraform.Block) securitycenter.SubscriptionPricing {
	tierAttr := resource.GetAttribute("tier")
	tierVal := tierAttr.AsStringValueOrDefault("Free", resource)

	return securitycenter.SubscriptionPricing{
		Metadata: resource.GetMetadata(),
		Tier:     tierVal,
	}
}
