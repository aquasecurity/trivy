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

	return securitycenter.Contact{
		Metadata:                 resource.Metadata,
		EnableAlertNotifications: resource.Properties.GetMapValue("alertNotifications").AsBoolValue(false, resource.Metadata),
		EnableAlertsToAdmins:     iacTypes.Bool(alertsToAdminsState.EqualTo("On"), resource.Metadata),
		Email:                    resource.Properties.GetMapValue("emails").AsStringValue("", resource.Metadata),
		Phone:                    resource.Properties.GetMapValue("phone").AsStringValue("", resource.Metadata),
	}
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
