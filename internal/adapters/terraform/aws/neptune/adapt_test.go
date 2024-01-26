package neptune

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/neptune"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptCluster(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  neptune.Cluster
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_neptune_cluster" "example" {
				enable_cloudwatch_logs_exports      = ["audit"]
				storage_encrypted                   = true
				kms_key_arn                         = "kms-key"
			  }
`,
			expected: neptune.Cluster{
				Metadata: defsecTypes.NewTestMetadata(),
				Logging: neptune.Logging{
					Metadata: defsecTypes.NewTestMetadata(),
					Audit:    defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				},
				StorageEncrypted: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				KMSKeyID:         defsecTypes.String("kms-key", defsecTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_neptune_cluster" "example" {
			  }
`,
			expected: neptune.Cluster{
				Metadata: defsecTypes.NewTestMetadata(),
				Logging: neptune.Logging{
					Metadata: defsecTypes.NewTestMetadata(),
					Audit:    defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				},
				StorageEncrypted: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				KMSKeyID:         defsecTypes.String("", defsecTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptCluster(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_neptune_cluster" "example" {
		enable_cloudwatch_logs_exports      = ["audit"]
		storage_encrypted                   = true
		kms_key_arn                         = "kms-key"
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	cluster := adapted.Clusters[0]

	assert.Equal(t, 2, cluster.Metadata.Range().GetStartLine())
	assert.Equal(t, 6, cluster.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, cluster.Logging.Metadata.Range().GetStartLine())
	assert.Equal(t, 3, cluster.Logging.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, cluster.Logging.Audit.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, cluster.Logging.Audit.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, cluster.StorageEncrypted.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, cluster.StorageEncrypted.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, cluster.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, cluster.KMSKeyID.GetMetadata().Range().GetEndLine())
}
