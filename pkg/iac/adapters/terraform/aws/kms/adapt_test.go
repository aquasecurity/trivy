package kms

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/kms"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptKey(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  kms.Key
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_kms_key" "example" {
				enable_key_rotation = true
				key_usage = "SIGN_VERIFY"
			}
`,
			expected: kms.Key{
				Usage:           iacTypes.String(kms.KeyUsageSignAndVerify, iacTypes.NewTestMetadata()),
				RotationEnabled: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_kms_key" "example" {
			}
`,
			expected: kms.Key{
				Usage:           iacTypes.String("ENCRYPT_DECRYPT", iacTypes.NewTestMetadata()),
				RotationEnabled: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptKey(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_kms_key" "example" {
		enable_key_rotation = true
		key_usage = SIGN_VERIFY
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Keys, 1)
	key := adapted.Keys[0]

	assert.Equal(t, 2, key.Metadata.Range().GetStartLine())
	assert.Equal(t, 5, key.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, key.RotationEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, key.RotationEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, key.Usage.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, key.Usage.GetMetadata().Range().GetEndLine())

}
