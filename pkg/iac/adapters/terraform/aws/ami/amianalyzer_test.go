package ami

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ami"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_AMI(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected ami.AMI
	}{
		{
			name: "AMI with single owner",
			input: `
resource "aws_ami" "example" {
    owners = ["amazon"]
}`,
			expected: ami.AMI{
				Metadata: iacTypes.NewTestMetadata(),
				Owners: iacTypes.StringValueList{
					iacTypes.StringTest("amazon"),
				}},
		},
		{
			name: "AMI with multiple owners",
			input: `
resource "aws_ami" "example" {
    owners = ["amazon", "badguys"]
}`,
			expected: ami.AMI{
				Metadata: iacTypes.NewTestMetadata(),
				Owners: iacTypes.StringValueList{
					iacTypes.StringTest("amazon"),
					iacTypes.StringTest("badguys"),
				},
			},
		},
		{
			name: "AMI without owner",
			input: `
resource "aws_ami" "example" {
    name = "test-ami"
}`,
			expected: ami.AMI{
				Metadata: iacTypes.NewTestMetadata(),
				Owners:   nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, tt.input, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, tt.expected, adapted)
		})
	}
}
