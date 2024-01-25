package dns

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/providers/nifcloud/dns"
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
)

func Test_adaptRecords(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []dns.Record
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_dns_record" "example" {
				type    = "A"
				record  = "example-record"
			}
`,
			expected: []dns.Record{{
				Metadata: defsecTypes.NewTestMisconfigMetadata(),
				Type:     defsecTypes.String("A", defsecTypes.NewTestMisconfigMetadata()),
				Record:   defsecTypes.String("example-record", defsecTypes.NewTestMisconfigMetadata()),
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_dns_record" "example" {
			}
`,

			expected: []dns.Record{{
				Metadata: defsecTypes.NewTestMisconfigMetadata(),
				Type:     defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
				Record:   defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptRecords(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
