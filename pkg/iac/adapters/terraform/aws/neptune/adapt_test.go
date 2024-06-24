package neptune

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/neptune"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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
				Metadata: iacTypes.NewTestMetadata(),
				Logging: neptune.Logging{
					Metadata: iacTypes.NewTestMetadata(),
					Audit:    iacTypes.Bool(true, iacTypes.NewTestMetadata()),
				},
				StorageEncrypted: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
				KMSKeyID:         iacTypes.String("kms-key", iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_neptune_cluster" "example" {
			  }
`,
			expected: neptune.Cluster{
				Metadata: iacTypes.NewTestMetadata(),
				Logging: neptune.Logging{
					Metadata: iacTypes.NewTestMetadata(),
					Audit:    iacTypes.Bool(false, iacTypes.NewTestMetadata()),
				},
				StorageEncrypted: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
				KMSKeyID:         iacTypes.String("", iacTypes.NewTestMetadata()),
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
