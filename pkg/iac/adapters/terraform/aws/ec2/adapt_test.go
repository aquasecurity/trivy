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

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ec2.EC2
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_instance" "example" {
				ami = "ami-7f89a64f"
				instance_type = "t1.micro"
			  
				root_block_device {
					encrypted = true
				}

				metadata_options {
					http_tokens = "required"
					http_endpoint = "disabled"
				}	
			  
				ebs_block_device {
				  encrypted = true
				}

				user_data = <<EOF
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
				EOF
			}
`,
			expected: ec2.EC2{
				Instances: []ec2.Instance{
					{
						Metadata: iacTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     iacTypes.NewTestMetadata(),
							HttpTokens:   iacTypes.String("required", iacTypes.NewTestMetadata()),
							HttpEndpoint: iacTypes.String("disabled", iacTypes.NewTestMetadata()),
						},
						UserData: iacTypes.String(
							`export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
`,
							iacTypes.NewTestMetadata()),
						RootBlockDevice: &ec2.BlockDevice{
							Metadata:  iacTypes.NewTestMetadata(),
							Encrypted: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
						},
						EBSBlockDevices: []*ec2.BlockDevice{
							{
								Metadata:  iacTypes.NewTestMetadata(),
								Encrypted: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_instance" "example" {
			}
`,
			expected: ec2.EC2{
				Instances: []ec2.Instance{
					{
						Metadata: iacTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     iacTypes.NewTestMetadata(),
							HttpTokens:   iacTypes.String("", iacTypes.NewTestMetadata()),
							HttpEndpoint: iacTypes.String("", iacTypes.NewTestMetadata()),
						},
						UserData: iacTypes.String("", iacTypes.NewTestMetadata()),
						RootBlockDevice: &ec2.BlockDevice{
							Metadata:  iacTypes.NewTestMetadata(),
							Encrypted: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "ec2 instance with launch template, ref to id",
			terraform: `
resource "aws_launch_template" "this" {
  metadata_options {
    http_endpoint               = "disabled"
    http_tokens                 = "required"
  }
}

resource "aws_instance" "this" {
  launch_template {
    id = aws_launch_template.this.id
  }
}
`,
			expected: ec2.EC2{
				LaunchTemplates: []ec2.LaunchTemplate{
					{
						Metadata: iacTypes.NewTestMetadata(),
						Instance: ec2.Instance{
							Metadata: iacTypes.NewTestMetadata(),
							MetadataOptions: ec2.MetadataOptions{
								HttpEndpoint: iacTypes.String("disabled", iacTypes.NewTestMetadata()),
								HttpTokens:   iacTypes.String("required", iacTypes.NewTestMetadata()),
							},
						},
					},
				},
				Instances: []ec2.Instance{
					{
						Metadata: iacTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							HttpEndpoint: iacTypes.String("disabled", iacTypes.NewTestMetadata()),
							HttpTokens:   iacTypes.String("required", iacTypes.NewTestMetadata()),
						},
						RootBlockDevice: &ec2.BlockDevice{
							Metadata:  iacTypes.NewTestMetadata(),
							Encrypted: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "ec2 instance with launch template, ref to name",
			terraform: `
resource "aws_launch_template" "this" {
  name = "testname"
  metadata_options {
    http_endpoint = "disabled"
    http_tokens   = "required"
  }
}

resource "aws_instance" "this" {
  launch_template {
    name = aws_launch_template.this.name
  }
}
`,
			expected: ec2.EC2{
				LaunchTemplates: []ec2.LaunchTemplate{
					{
						Metadata: iacTypes.NewTestMetadata(),
						Instance: ec2.Instance{
							Metadata: iacTypes.NewTestMetadata(),
							MetadataOptions: ec2.MetadataOptions{
								HttpEndpoint: iacTypes.String("disabled", iacTypes.NewTestMetadata()),
								HttpTokens:   iacTypes.String("required", iacTypes.NewTestMetadata()),
							},
						},
					},
				},
				Instances: []ec2.Instance{
					{
						Metadata: iacTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							HttpEndpoint: iacTypes.String("disabled", iacTypes.NewTestMetadata()),
							HttpTokens:   iacTypes.String("required", iacTypes.NewTestMetadata()),
						},
						RootBlockDevice: &ec2.BlockDevice{
							Metadata:  iacTypes.NewTestMetadata(),
							Encrypted: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_instance" "example" {
		ami = "ami-7f89a64f"
		instance_type = "t1.micro"
	  
		root_block_device {
			encrypted = true
		}

		metadata_options {
			http_tokens = "required"
			http_endpoint = "disabled"
		}	
	  
		ebs_block_device {
		  encrypted = true
		}

		user_data = <<EOF
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
		EOF
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Instances, 1)
	instance := adapted.Instances[0]

	assert.Equal(t, 2, instance.Metadata.Range().GetStartLine())
	assert.Equal(t, 22, instance.Metadata.Range().GetEndLine())

	assert.Equal(t, 6, instance.RootBlockDevice.Metadata.Range().GetStartLine())
	assert.Equal(t, 8, instance.RootBlockDevice.Metadata.Range().GetEndLine())

	assert.Equal(t, 7, instance.RootBlockDevice.Encrypted.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, instance.RootBlockDevice.Encrypted.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, instance.MetadataOptions.Metadata.Range().GetStartLine())
	assert.Equal(t, 13, instance.MetadataOptions.Metadata.Range().GetEndLine())

	assert.Equal(t, 11, instance.MetadataOptions.HttpTokens.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, instance.MetadataOptions.HttpTokens.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 12, instance.MetadataOptions.HttpEndpoint.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 12, instance.MetadataOptions.HttpEndpoint.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, instance.EBSBlockDevices[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 17, instance.EBSBlockDevices[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 16, instance.EBSBlockDevices[0].Encrypted.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, instance.EBSBlockDevices[0].Encrypted.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 19, instance.UserData.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 21, instance.UserData.GetMetadata().Range().GetEndLine())
}
