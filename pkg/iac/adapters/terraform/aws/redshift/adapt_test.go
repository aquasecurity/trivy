package redshift

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/redshift"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  redshift.Redshift
	}{
		{
			name: "reference key id",
			terraform: `
			resource "aws_kms_key" "redshift" {
				enable_key_rotation = true
			}
			
			resource "aws_redshift_cluster" "example" {
			  cluster_identifier = "tf-redshift-cluster"
			  publicly_accessible = false
			  number_of_nodes = 1
			  allow_version_upgrade = false
			  port = 5440
			  encrypted          = true
			  kms_key_id         = aws_kms_key.redshift.key_id
			  cluster_subnet_group_name = "redshift_subnet"
			}

			resource "aws_redshift_security_group" "default" {
				name = "redshift-sg"
				description = "some description"
			}
`,
			expected: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						ClusterIdentifier: iacTypes.StringTest("tf-redshift-cluster"),
						NumberOfNodes:     iacTypes.IntTest(1),
						EndPoint: redshift.EndPoint{
							Port: iacTypes.IntTest(5440),
						},
						Encryption: redshift.Encryption{
							Enabled:  iacTypes.BoolTest(true),
							KMSKeyID: iacTypes.StringTest("aws_kms_key.redshift"),
						},
						SubnetGroupName: iacTypes.StringTest("redshift_subnet"),
					},
				},
				SecurityGroups: []redshift.SecurityGroup{
					{
						Description: iacTypes.StringTest("some description"),
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

func Test_adaptCluster(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  redshift.Cluster
	}{
		{
			name: "key as string",
			terraform: `			
			resource "aws_redshift_cluster" "example" {
			  cluster_identifier = "tf-redshift-cluster"
			  publicly_accessible = false
			  number_of_nodes = 1
			  allow_version_upgrade = false
			  port = 5440
			  encrypted          = true
			  kms_key_id         = "key-id"
			  cluster_subnet_group_name = "redshift_subnet"
			}
`,
			expected: redshift.Cluster{
				ClusterIdentifier: iacTypes.StringTest("tf-redshift-cluster"),
				NumberOfNodes:     iacTypes.IntTest(1),
				EndPoint: redshift.EndPoint{
					Port: iacTypes.IntTest(5440),
				},
				Encryption: redshift.Encryption{
					Enabled:  iacTypes.BoolTest(true),
					KMSKeyID: iacTypes.StringTest("key-id"),
				},
				SubnetGroupName: iacTypes.StringTest("redshift_subnet"),
			},
		},
		{
			name: "defaults",
			terraform: `			
			resource "aws_redshift_cluster" "example" {
			}
`,
			expected: redshift.Cluster{
				PubliclyAccessible:  iacTypes.BoolTest(true),
				NumberOfNodes:       iacTypes.IntTest(1),
				AllowVersionUpgrade: iacTypes.BoolTest(true),
				EndPoint: redshift.EndPoint{
					Port: iacTypes.IntTest(5439),
				},
				Encryption: redshift.Encryption{},
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

func Test_adaptSecurityGroup(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  redshift.SecurityGroup
	}{
		{
			name: "defaults",
			terraform: `
resource "" "example" {
}
`,
			expected: redshift.SecurityGroup{
				Description: iacTypes.StringTest("Managed by Terraform"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptSecurityGroup(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_kms_key" "redshift" {
		enable_key_rotation = true
	}
	
	resource "aws_redshift_cluster" "example" {
	  cluster_identifier = "tf-redshift-cluster"
	  encrypted          = true
	  kms_key_id         = aws_kms_key.redshift.key_id
	  cluster_subnet_group_name = "subnet name"
	}

	resource "aws_redshift_security_group" "default" {
		name = "redshift-sg"
		description = "some description"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	require.Len(t, adapted.SecurityGroups, 1)
	cluster := adapted.Clusters[0]
	securityGroup := adapted.SecurityGroups[0]

	assert.Equal(t, 6, cluster.Metadata.Range().GetStartLine())
	assert.Equal(t, 11, cluster.Metadata.Range().GetEndLine())

	assert.Equal(t, 8, cluster.Encryption.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 8, cluster.Encryption.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 2, cluster.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, cluster.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, cluster.SubnetGroupName.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, cluster.SubnetGroupName.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, securityGroup.Metadata.Range().GetStartLine())
	assert.Equal(t, 16, securityGroup.Metadata.Range().GetEndLine())

	assert.Equal(t, 15, securityGroup.Description.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, securityGroup.Description.GetMetadata().Range().GetEndLine())
}
