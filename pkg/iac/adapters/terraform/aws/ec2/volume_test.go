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

func Test_adaptVolume(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ec2.Volume
	}{
		{
			name: "referenced key",
			terraform: `
			resource "aws_ebs_volume" "example" {
				kms_key_id = aws_kms_key.ebs_encryption.arn
				encrypted = true
			}

			resource "aws_kms_key" "ebs_encryption" {
				enable_key_rotation = true
			}
`,
			expected: ec2.Volume{
				Metadata: iacTypes.NewTestMetadata(),
				Encryption: ec2.Encryption{
					Metadata: iacTypes.NewTestMetadata(),
					Enabled:  iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					KMSKeyID: iacTypes.String("aws_kms_key.ebs_encryption", iacTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "string key",
			terraform: `
			resource "aws_ebs_volume" "example" {
				kms_key_id = "string-key"
				encrypted = true
			}
`,
			expected: ec2.Volume{
				Metadata: iacTypes.NewTestMetadata(),
				Encryption: ec2.Encryption{
					Metadata: iacTypes.NewTestMetadata(),
					Enabled:  iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					KMSKeyID: iacTypes.String("string-key", iacTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_ebs_volume" "example" {
			}
`,
			expected: ec2.Volume{
				Metadata: iacTypes.NewTestMetadata(),
				Encryption: ec2.Encryption{
					Metadata: iacTypes.NewTestMetadata(),
					Enabled:  iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					KMSKeyID: iacTypes.String("", iacTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptVolume(modules.GetBlocks()[0], modules[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestVolumeLines(t *testing.T) {
	src := `
	resource "aws_ebs_volume" "example" {
		kms_key_id = aws_kms_key.ebs_encryption.arn
		encrypted = true
	}

	resource "aws_kms_key" "ebs_encryption" {
		enable_key_rotation = true
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Volumes, 1)
	volume := adapted.Volumes[0]

	assert.Equal(t, 2, volume.Metadata.Range().GetStartLine())
	assert.Equal(t, 5, volume.Metadata.Range().GetEndLine())

	assert.Equal(t, 4, volume.Encryption.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, volume.Encryption.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, volume.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, volume.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())
}
