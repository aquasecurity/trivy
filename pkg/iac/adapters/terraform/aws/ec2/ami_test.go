package ec2

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdaptAMIs(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		expected ec2.EC2
	}{
		{
			name: "AMI with single owner",
			src: `
data "aws_ami" "example" {
    owners = ["amazon"]
}`,
			expected: ec2.EC2{
				RequestedAMIs: []ec2.RequestedAMI{
					{
						Metadata: iacTypes.NewTestMetadata(),
						Owners: iacTypes.StringValueList{
							iacTypes.StringTest("amazon"),
						},
					},
				},
			},
		},
		{
			name: "AMI with multiple owners",
			src: `
data "aws_ami" "example" {
    owners = ["amazon", "badguys"]
}`,
			expected: ec2.EC2{
				RequestedAMIs: []ec2.RequestedAMI{
					{
						Metadata: iacTypes.NewTestMetadata(),
						Owners: iacTypes.StringValueList{
							iacTypes.StringTest("amazon"),
							iacTypes.StringTest("badguys"),
						},
					},
				},
			},
		},
		{
			name: "AMI without owner",
			src: `
data "aws_ami" "example" {
    name = "test-ami"
}`,
			expected: ec2.EC2{
				RequestedAMIs: []ec2.RequestedAMI{
					{
						Metadata: iacTypes.NewTestMetadata(),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, tt.src, ".tf")
			testutil.AssertDefsecEqual(t, tt.expected, Adapt(modules))
		})
	}
}
