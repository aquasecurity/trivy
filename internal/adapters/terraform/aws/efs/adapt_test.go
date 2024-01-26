package efs

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/efs"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptFileSystem(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  efs.FileSystem
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_efs_file_system" "example" {
				name       = "bar"
				encrypted  = true
				kms_key_id = "my_kms_key"
			  }
`,
			expected: efs.FileSystem{
				Metadata:  defsecTypes.NewTestMetadata(),
				Encrypted: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_efs_file_system" "example" {
			  }
`,
			expected: efs.FileSystem{
				Metadata:  defsecTypes.NewTestMetadata(),
				Encrypted: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptFileSystem(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_efs_file_system" "example" {
		name       = "bar"
		encrypted  = true
		kms_key_id = "my_kms_key"
	  }
	`
	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.FileSystems, 1)
	fileSystem := adapted.FileSystems[0]

	assert.Equal(t, 2, fileSystem.Metadata.Range().GetStartLine())
	assert.Equal(t, 6, fileSystem.Metadata.Range().GetEndLine())

	assert.Equal(t, 4, fileSystem.Encrypted.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, fileSystem.Encrypted.GetMetadata().Range().GetEndLine())
}
