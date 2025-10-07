package securitycenter

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/securitycenter"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
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
	return securitycenter.Contact{
		Metadata: resource.Metadata,
		// TODO: The email field does not exist
		// https://learn.microsoft.com/en-us/azure/templates/microsoft.security/securitycontacts?pivots=deployment-language-arm-template#securitycontactproperties-1
		EnableAlertNotifications: resource.Properties.GetMapValue("email").AsBoolValue(false, resource.Metadata),
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
