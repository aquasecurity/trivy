package documentdb

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/documentdb"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				Metadata:   defsecTypes.NewTestMetadata(),
				Identifier: defsecTypes.String("my-docdb-cluster", defsecTypes.NewTestMetadata()),
				KMSKeyID:   defsecTypes.String("kms-key", defsecTypes.NewTestMetadata()),
				EnabledLogExports: []defsecTypes.StringValue{
					defsecTypes.String("audit", defsecTypes.NewTestMetadata()),
				},
				Instances: []documentdb.Instance{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						KMSKeyID: defsecTypes.String("kms-key#1", defsecTypes.NewTestMetadata()),
					},
				},
				StorageEncrypted: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `		
			resource "aws_docdb_cluster" "docdb" {
			}
`,
			expected: documentdb.Cluster{
				Metadata:         defsecTypes.NewTestMetadata(),
				Identifier:       defsecTypes.String("", defsecTypes.NewTestMetadata()),
				StorageEncrypted: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				KMSKeyID:         defsecTypes.String("", defsecTypes.NewTestMetadata()),
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
