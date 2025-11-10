package ec2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptSubnet(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ec2.Subnet
	}{
		{
			name: "map public ip on launch is true",
			terraform: `
			resource "aws_subnet" "example" {
				vpc_id                  = "vpc-123456"
				map_public_ip_on_launch = true
			}
`,
			expected: ec2.Subnet{
				Metadata:            iacTypes.NewTestMetadata(),
				MapPublicIpOnLaunch: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "map public ip on launch is false",
			terraform: `
			resource "aws_subnet" "example" {
				vpc_id                  = "vpc-123456"
				map_public_ip_on_launch = false
			}
`,
			expected: ec2.Subnet{
				Metadata:            iacTypes.NewTestMetadata(),
				MapPublicIpOnLaunch: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_subnet" "example" {
			    vpc_id = "vpc-123456"
			}
`,
			expected: ec2.Subnet{
				Metadata:            iacTypes.NewTestMetadata(),
				MapPublicIpOnLaunch: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptSubnet(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestSubnetLines(t *testing.T) {
	src := `
	resource "aws_subnet" "example" {
	    vpc_id                  = "vpc-123456"
	    map_public_ip_on_launch = true
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Subnets, 1)
	subnet := adapted.Subnets[0]

	assert.Equal(t, 2, subnet.Metadata.Range().GetStartLine())
	assert.Equal(t, 5, subnet.Metadata.Range().GetEndLine())

	assert.Equal(t, 4, subnet.MapPublicIpOnLaunch.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, subnet.MapPublicIpOnLaunch.GetMetadata().Range().GetEndLine())
}
