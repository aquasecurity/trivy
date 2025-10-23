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
				Contacts: []securitycenter.Contact{{
					IsEnabled:            types.BoolTest(false),
					EnableAlertsToAdmins: types.BoolTest(false),
					Email:                types.StringTest(""),
					Phone:                types.StringTest(""),
					NotificationsSources: []securitycenter.NotificationSource{},
				}},
				Subscriptions: []securitycenter.SubscriptionPricing{{
					Tier: types.StringTest("Free"),
				}},
			},
		},
		{
			name: "complete",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Security/securityContacts",
      "properties": {
        "emails": "security@example.com",
        "phone": "buz",
        "isEnabled": true,
        "notificationsByRole": {
          "state": "On"
        },
        "notificationsSources": [
          {
            "sourceType": "Alert",
            "minimalSeverity": "High"
          }
        ]
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
					Email:                types.StringTest("security@example.com"),
					Phone:                types.StringTest("buz"),
					IsEnabled:            types.BoolTest(true),
					EnableAlertsToAdmins: types.BoolTest(true),
					NotificationsSources: []securitycenter.NotificationSource{{
						SourceType:      types.StringTest("Alert"),
						MinimalSeverity: types.StringTest("High"),
					}},
				}},
				Subscriptions: []securitycenter.SubscriptionPricing{{
					Tier: types.StringTest("Standard"),
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
