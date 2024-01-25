package ec2

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy/pkg/providers/aws/ec2"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				Metadata: defsecTypes.NewTestMisconfigMetadata(),
				Encryption: ec2.Encryption{
					Metadata: defsecTypes.NewTestMisconfigMetadata(),
					Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),
					KMSKeyID: defsecTypes.String("aws_kms_key.ebs_encryption", defsecTypes.NewTestMisconfigMetadata()),
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
				Metadata: defsecTypes.NewTestMisconfigMetadata(),
				Encryption: ec2.Encryption{
					Metadata: defsecTypes.NewTestMisconfigMetadata(),
					Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),
					KMSKeyID: defsecTypes.String("string-key", defsecTypes.NewTestMisconfigMetadata()),
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
				Metadata: defsecTypes.NewTestMisconfigMetadata(),
				Encryption: ec2.Encryption{
					Metadata: defsecTypes.NewTestMisconfigMetadata(),
					Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
					KMSKeyID: defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
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
