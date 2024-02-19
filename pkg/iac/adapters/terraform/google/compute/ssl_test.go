package compute

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/compute"
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
					Metadata:          iacTypes.NewTestMetadata(),
					Name:              iacTypes.String("production-ssl-policy", iacTypes.NewTestMetadata()),
					Profile:           iacTypes.String("MODERN", iacTypes.NewTestMetadata()),
					MinimumTLSVersion: iacTypes.String("TLS_1_2", iacTypes.NewTestMetadata()),
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
					Metadata:          iacTypes.NewTestMetadata(),
					Name:              iacTypes.String("", iacTypes.NewTestMetadata()),
					Profile:           iacTypes.String("", iacTypes.NewTestMetadata()),
					MinimumTLSVersion: iacTypes.String("TLS_1_0", iacTypes.NewTestMetadata()),
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
