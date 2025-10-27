package securitycenter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/securitycenter"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptContact(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  securitycenter.Contact
	}{
		{
			name: "defined",
			terraform: `
			resource "azurerm_security_center_contact" "example" {
				email = "contact@example.com"
				phone = "+1-555-555-5555"
				alert_notifications = true
				alerts_to_admins = true
			}
`,
			expected: securitycenter.Contact{
				Metadata:                 iacTypes.NewTestMetadata(),
				EnableAlertNotifications: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
				EnableAlertsToAdmins:     iacTypes.Bool(true, iacTypes.NewTestMetadata()),
				Email:                    iacTypes.String("contact@example.com", iacTypes.NewTestMetadata()),
				Phone:                    iacTypes.String("+1-555-555-5555", iacTypes.NewTestMetadata()),
				IsEnabled:                iacTypes.BoolValue{},
				MinimalSeverity:          iacTypes.StringValue{},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "azurerm_security_center_contact" "example" {
			}
`,
			expected: securitycenter.Contact{
				Metadata:                 iacTypes.NewTestMetadata(),
				EnableAlertNotifications: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
				EnableAlertsToAdmins:     iacTypes.Bool(false, iacTypes.NewTestMetadata()),
				Email:                    iacTypes.String("", iacTypes.NewTestMetadata()),
				Phone:                    iacTypes.String("", iacTypes.NewTestMetadata()),
				IsEnabled:                iacTypes.BoolValue{},
				MinimalSeverity:          iacTypes.StringValue{},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptContact(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptSubscription(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  securitycenter.SubscriptionPricing
	}{
		{
			name: "free tier",
			terraform: `
			resource "azurerm_security_center_subscription_pricing" "example" {
				tier          = "Free"
			}`,
			expected: securitycenter.SubscriptionPricing{
				Metadata: iacTypes.NewTestMetadata(),
				Tier:     iacTypes.String("Free", iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "default - free tier",
			terraform: `
			resource "azurerm_security_center_subscription_pricing" "example" {
			}`,
			expected: securitycenter.SubscriptionPricing{
				Metadata: iacTypes.NewTestMetadata(),
				Tier:     iacTypes.String("Free", iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "standard tier",
			terraform: `
			resource "azurerm_security_center_subscription_pricing" "example" {
				tier          = "Standard"
			}`,
			expected: securitycenter.SubscriptionPricing{
				Metadata: iacTypes.NewTestMetadata(),
				Tier:     iacTypes.String("Standard", iacTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptSubscription(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_security_center_contact" "example" {
		email = "contact@example.com"
		phone = "+1-555-555-5555"
		alert_notifications = true
		alerts_to_admins = true
	}

	resource "azurerm_security_center_subscription_pricing" "example" {
		tier          = "Standard"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Contacts, 1)
	require.Len(t, adapted.Subscriptions, 1)

	contact := adapted.Contacts[0]
	sub := adapted.Subscriptions[0]

	assert.Equal(t, 3, contact.Email.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, contact.Email.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, contact.Phone.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, contact.Phone.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, contact.EnableAlertNotifications.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, contact.EnableAlertNotifications.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, contact.EnableAlertsToAdmins.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, contact.EnableAlertsToAdmins.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, sub.Tier.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, sub.Tier.GetMetadata().Range().GetEndLine())
}
