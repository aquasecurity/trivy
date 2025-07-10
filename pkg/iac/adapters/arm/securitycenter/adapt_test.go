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
			name: "complete",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Security/securityContacts",
      "properties": {
        "phone": "buz"
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
					Phone: types.StringTest("buz"),
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
