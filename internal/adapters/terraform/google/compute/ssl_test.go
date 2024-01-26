package compute

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/google/compute"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/test/testutil"
)

func Test_adaptSSLPolicies(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []compute.SSLPolicy
	}{
		{
			name: "defined",
			terraform: `
			resource "google_compute_ssl_policy" "example" {
				name    = "production-ssl-policy"
				profile = "MODERN"
				min_tls_version = "TLS_1_2"
			  }
`,
			expected: []compute.SSLPolicy{
				{
					Metadata:          defsecTypes.NewTestMetadata(),
					Name:              defsecTypes.String("production-ssl-policy", defsecTypes.NewTestMetadata()),
					Profile:           defsecTypes.String("MODERN", defsecTypes.NewTestMetadata()),
					MinimumTLSVersion: defsecTypes.String("TLS_1_2", defsecTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "google_compute_ssl_policy" "example" {
			  }
`,
			expected: []compute.SSLPolicy{
				{
					Metadata:          defsecTypes.NewTestMetadata(),
					Name:              defsecTypes.String("", defsecTypes.NewTestMetadata()),
					Profile:           defsecTypes.String("", defsecTypes.NewTestMetadata()),
					MinimumTLSVersion: defsecTypes.String("TLS_1_0", defsecTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptSSLPolicies(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
