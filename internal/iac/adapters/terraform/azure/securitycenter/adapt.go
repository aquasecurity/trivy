package securitycenter

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/securitycenter"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
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
	enableAlertNotifAttr := resource.GetAttribute("alert_notifications")
	enableAlertNotifVal := enableAlertNotifAttr.AsBoolValueOrDefault(false, resource)

	phoneAttr := resource.GetAttribute("phone")
	phoneVal := phoneAttr.AsStringValueOrDefault("", resource)

	return securitycenter.Contact{
		Metadata:                 resource.GetMetadata(),
		EnableAlertNotifications: enableAlertNotifVal,
		Phone:                    phoneVal,
	}
}

func adaptSubscription(resource *terraform.Block) securitycenter.SubscriptionPricing {
	tierAttr := resource.GetAttribute("tier")
	tierVal := tierAttr.AsStringValueOrDefault("Free", resource)

	return securitycenter.SubscriptionPricing{
		Metadata: resource.GetMetadata(),
		Tier:     tierVal,
	}
}
