package compute

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/cloudstack/compute"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptInstance(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  compute.Instance
	}{
		{
			name: "sensitive user data",
			terraform: `
			resource "cloudstack_instance" "web" {
				name             = "server-1"
				user_data        = <<EOF
export DATABASE_PASSWORD=\"SomeSortOfPassword\"
			EOF
			}
`,
			expected: compute.Instance{
				Metadata: iacTypes.NewTestMetadata(),
				UserData: iacTypes.String(`export DATABASE_PASSWORD=\"SomeSortOfPassword\"
`, iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "sensitive user data base64 encoded",
			terraform: `
			resource "cloudstack_instance" "web" {
				name             = "server-1"
				user_data        = "ZXhwb3J0IERBVEFCQVNFX1BBU1NXT1JEPSJTb21lU29ydE9mUGFzc3dvcmQi"
			}
`,
			expected: compute.Instance{
				Metadata: iacTypes.NewTestMetadata(),
				UserData: iacTypes.String(`export DATABASE_PASSWORD="SomeSortOfPassword"`, iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "no user data provided",
			terraform: `
			resource "cloudstack_instance" "web" {
			}
`,
			expected: compute.Instance{
				Metadata: iacTypes.NewTestMetadata(),
				UserData: iacTypes.String("", iacTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptInstance(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "cloudstack_instance" "web" {
		name             = "server-1"
		user_data        = <<EOF
export DATABASE_PASSWORD=\"SomeSortOfPassword\"
	EOF
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Instances, 1)
	instance := adapted.Instances[0]

	assert.Equal(t, 4, instance.UserData.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, instance.UserData.GetMetadata().Range().GetEndLine())
}
