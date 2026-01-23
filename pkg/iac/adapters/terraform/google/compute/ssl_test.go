package compute

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/compute"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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
					Name:              iacTypes.StringTest("production-ssl-policy"),
					Profile:           iacTypes.StringTest("MODERN"),
					MinimumTLSVersion: iacTypes.StringTest("TLS_1_2"),
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
					MinimumTLSVersion: iacTypes.StringTest("TLS_1_0"),
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
