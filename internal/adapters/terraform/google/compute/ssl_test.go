package compute

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy/pkg/providers/google/compute"

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
					Metadata:          defsecTypes.NewTestMisconfigMetadata(),
					Name:              defsecTypes.String("production-ssl-policy", defsecTypes.NewTestMisconfigMetadata()),
					Profile:           defsecTypes.String("MODERN", defsecTypes.NewTestMisconfigMetadata()),
					MinimumTLSVersion: defsecTypes.String("TLS_1_2", defsecTypes.NewTestMisconfigMetadata()),
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
					Metadata:          defsecTypes.NewTestMisconfigMetadata(),
					Name:              defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
					Profile:           defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
					MinimumTLSVersion: defsecTypes.String("TLS_1_0", defsecTypes.NewTestMisconfigMetadata()),
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
