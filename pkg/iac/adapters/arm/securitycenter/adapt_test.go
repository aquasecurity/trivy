package securitycenter

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/arm/adaptertest"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/securitycenter"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected securitycenter.SecurityCenter
	}{
		{
			name: "empty",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Security/securityContacts",
      "properties": {}
    },
    {
      "type": "Microsoft.Security/pricings",
      "properties": {}
    }
  ]
}`,
			expected: securitycenter.SecurityCenter{
				Contacts: []securitycenter.Contact{{}},
				Subscriptions: []securitycenter.SubscriptionPricing{{
					Tier: types.StringTest("Free"),
				}},
			},
		},
		{
			name: "complete - legacy format",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Security/securityContacts",
      "properties": {
        "emails": "security@example.com",
        "phone": "buz",
        "alertNotifications": true,
        "notificationsByRole": {
          "state": "On"
        }
      }
    },
    {
      "type": "Microsoft.Security/pricings",
      "properties": {
        "pricingTier": "Standard"
      }
    }
  ]
}`,
			expected: securitycenter.SecurityCenter{
				Contacts: []securitycenter.Contact{{
					Email:                    types.StringTest("security@example.com"),
					Phone:                    types.StringTest("buz"),
					EnableAlertNotifications: types.BoolTest(true),
					EnableAlertsToAdmins:     types.BoolTest(true),
				}},
				Subscriptions: []securitycenter.SubscriptionPricing{{
					Tier: types.StringTest("Standard"),
				}},
			},
		},
		{
			name: "complete - new format",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Security/securityContacts",
      "properties": {
        "emails": "security@example.com",
        "phone": "+1-555-555-5555",
        "isEnabled": true,
        "notificationsSources": [
          {
            "sourceType": "Alert",
            "minimalSeverity": "High"
          }
        ],
        "notificationsByRole": {
          "state": "On"
        }
      }
    },
    {
      "type": "Microsoft.Security/pricings",
      "properties": {
        "pricingTier": "Standard"
      }
    }
  ]
}`,
			expected: securitycenter.SecurityCenter{
				Contacts: []securitycenter.Contact{{
					Email:                    types.StringTest("security@example.com"),
					Phone:                    types.StringTest("+1-555-555-5555"),
					EnableAlertNotifications: types.BoolTest(true),
					EnableAlertsToAdmins:     types.BoolTest(true),
					IsEnabled:                types.BoolTest(true),
					MinimalSeverity:          types.StringTest("High"),
				}},
				Subscriptions: []securitycenter.SubscriptionPricing{{
					Tier: types.StringTest("Standard"),
				}},
			},
		},
		{
			name: "new format - disabled",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Security/securityContacts",
      "properties": {
        "emails": "security@example.com",
        "phone": "+1-555-555-5555",
        "isEnabled": false,
        "notificationsSources": [
          {
            "sourceType": "Alert", 
            "minimalSeverity": "Medium"
          }
        ],
        "notificationsByRole": {
          "state": "Off"
        }
      }
    }
  ]
}`,
			expected: securitycenter.SecurityCenter{
				Contacts: []securitycenter.Contact{{
					Email:                    types.StringTest("security@example.com"),
					Phone:                    types.StringTest("+1-555-555-5555"),
					EnableAlertNotifications: types.BoolTest(false),
					EnableAlertsToAdmins:     types.BoolTest(false),
					IsEnabled:                types.BoolTest(false),
					MinimalSeverity:          types.StringTest("Medium"),
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptertest.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}

}
