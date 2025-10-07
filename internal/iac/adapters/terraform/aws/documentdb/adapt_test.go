package documentdb

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/documentdb"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptCluster(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  documentdb.Cluster
	}{
		{
			name: "configured",
			terraform: `		
			resource "aws_docdb_cluster" "docdb" {
			  cluster_identifier      = "my-docdb-cluster"
			  kms_key_id 			  = "kms-key"
			  enabled_cloudwatch_logs_exports = "audit"
			  storage_encrypted = true
			}

			resource "aws_docdb_cluster_instance" "cluster_instances" {
				count              = 1
				identifier         = "my-docdb-cluster"
				cluster_identifier = aws_docdb_cluster.docdb.id
				kms_key_id 			  = "kms-key#1"
			  }
`,
			expected: documentdb.Cluster{
				Metadata:   iacTypes.NewTestMetadata(),
				Identifier: iacTypes.String("my-docdb-cluster", iacTypes.NewTestMetadata()),
				KMSKeyID:   iacTypes.String("kms-key", iacTypes.NewTestMetadata()),
				EnabledLogExports: []iacTypes.StringValue{
					iacTypes.String("audit", iacTypes.NewTestMetadata()),
				},
				Instances: []documentdb.Instance{
					{
						Metadata: iacTypes.NewTestMetadata(),
						KMSKeyID: iacTypes.String("kms-key#1", iacTypes.NewTestMetadata()),
					},
				},
				StorageEncrypted: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `		
			resource "aws_docdb_cluster" "docdb" {
			}
`,
			expected: documentdb.Cluster{
				Metadata:         iacTypes.NewTestMetadata(),
				Identifier:       iacTypes.String("", iacTypes.NewTestMetadata()),
				StorageEncrypted: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
				KMSKeyID:         iacTypes.String("", iacTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptCluster(modules.GetBlocks()[0], modules[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_docdb_cluster" "docdb" {
		cluster_identifier      = "my-docdb-cluster"
		kms_key_id 			  = "kms-key"
		enabled_cloudwatch_logs_exports = "audit"
		storage_encrypted = true
	}

 	resource "aws_docdb_cluster_instance" "cluster_instances" {
		count              	= 1
		identifier         	= "my-docdb-cluster"
		cluster_identifier 	= aws_docdb_cluster.docdb.id
		kms_key_id 		    = "kms-key"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	require.Len(t, adapted.Clusters[0].Instances, 1)

	cluster := adapted.Clusters[0]
	instance := cluster.Instances[0]

	assert.Equal(t, 2, cluster.Metadata.Range().GetStartLine())
	assert.Equal(t, 7, cluster.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, cluster.Identifier.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, cluster.Identifier.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, cluster.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, cluster.KMSKeyID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, cluster.EnabledLogExports[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, cluster.EnabledLogExports[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, cluster.StorageEncrypted.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, cluster.StorageEncrypted.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 9, instance.Metadata.Range().GetStartLine())
	assert.Equal(t, 14, instance.Metadata.Range().GetEndLine())

	assert.Equal(t, 13, instance.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 13, instance.KMSKeyID.GetMetadata().Range().GetEndLine())
}
