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

func adaptContacts(deployment azure.Deployment) (contacts []securitycenter.Contact) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.Security/securityContacts") {
		contacts = append(contacts, adaptContact(resource))
	}

	return contacts
}

func adaptContact(resource azure.Resource) securitycenter.Contact {
	alertsToAdminsState := resource.Properties.GetMapValue("notificationsByRole").GetMapValue("state").AsStringValue("", resource.Metadata)

	notificationsSources := adaptNotificationsSources(resource)

	return securitycenter.Contact{
		Metadata:             resource.Metadata,
		IsEnabled:            resource.Properties.GetMapValue("isEnabled").AsBoolValue(false, resource.Metadata),
		EnableAlertsToAdmins: iacTypes.Bool(alertsToAdminsState.EqualTo("On"), resource.Metadata),
		Email:                resource.Properties.GetMapValue("emails").AsStringValue("", resource.Metadata),
		Phone:                resource.Properties.GetMapValue("phone").AsStringValue("", resource.Metadata),
		NotificationsSources: notificationsSources,
	}
}

func adaptNotificationsSources(resource azure.Resource) []securitycenter.NotificationSource {
	var sources []securitycenter.NotificationSource

	notificationsSourcesArray := resource.Properties.GetMapValue("notificationsSources")
	if notificationsSourcesArray.Kind == azure.KindArray {
		for _, sourceItem := range notificationsSourcesArray.AsList() {
			if sourceItem.Kind == azure.KindObject {
				sourceMap := sourceItem.AsMap()
				sources = append(sources, securitycenter.NotificationSource{
					SourceType:      sourceMap["sourceType"].AsStringValue("", resource.Metadata),
					MinimalSeverity: sourceMap["minimalSeverity"].AsStringValue("", resource.Metadata),
				})
			}
		}
	}

	return sources
}

func adaptSubscriptions(deployment azure.Deployment) (subscriptions []securitycenter.SubscriptionPricing) {
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
