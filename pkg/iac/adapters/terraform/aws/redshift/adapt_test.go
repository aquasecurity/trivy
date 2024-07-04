package redshift

import (
	"fmt"
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
						Metadata:            iacTypes.NewTestMetadata(),
						ClusterIdentifier:   iacTypes.String("tf-redshift-cluster", iacTypes.NewTestMetadata()),
						PubliclyAccessible:  iacTypes.Bool(false, iacTypes.NewTestMetadata()),
						NumberOfNodes:       iacTypes.Int(1, iacTypes.NewTestMetadata()),
						AllowVersionUpgrade: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
						EndPoint: redshift.EndPoint{
							Metadata: iacTypes.NewTestMetadata(),
							Port:     iacTypes.Int(5440, iacTypes.NewTestMetadata()),
						},
						Encryption: redshift.Encryption{
							Metadata: iacTypes.NewTestMetadata(),
							Enabled:  iacTypes.Bool(true, iacTypes.NewTestMetadata()),
							KMSKeyID: iacTypes.String("aws_kms_key.redshift", iacTypes.NewTestMetadata()),
						},
						SubnetGroupName: iacTypes.String("redshift_subnet", iacTypes.NewTestMetadata()),
					},
				},
				SecurityGroups: []redshift.SecurityGroup{
					{
						Metadata:    iacTypes.NewTestMetadata(),
						Description: iacTypes.String("some description", iacTypes.NewTestMetadata()),
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			fmt.Println(adapted.SecurityGroups[0].Description.Value())
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
				Metadata:            iacTypes.NewTestMetadata(),
				ClusterIdentifier:   iacTypes.String("tf-redshift-cluster", iacTypes.NewTestMetadata()),
				PubliclyAccessible:  iacTypes.Bool(false, iacTypes.NewTestMetadata()),
				NumberOfNodes:       iacTypes.Int(1, iacTypes.NewTestMetadata()),
				AllowVersionUpgrade: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
				EndPoint: redshift.EndPoint{
					Metadata: iacTypes.NewTestMetadata(),
					Port:     iacTypes.Int(5440, iacTypes.NewTestMetadata()),
				},
				Encryption: redshift.Encryption{
					Metadata: iacTypes.NewTestMetadata(),
					Enabled:  iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					KMSKeyID: iacTypes.String("key-id", iacTypes.NewTestMetadata()),
				},
				SubnetGroupName: iacTypes.String("redshift_subnet", iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `			
			resource "aws_redshift_cluster" "example" {
			}
`,
			expected: redshift.Cluster{
				Metadata:            iacTypes.NewTestMetadata(),
				ClusterIdentifier:   iacTypes.String("", iacTypes.NewTestMetadata()),
				PubliclyAccessible:  iacTypes.Bool(true, iacTypes.NewTestMetadata()),
				NumberOfNodes:       iacTypes.Int(1, iacTypes.NewTestMetadata()),
				AllowVersionUpgrade: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
				EndPoint: redshift.EndPoint{
					Metadata: iacTypes.NewTestMetadata(),
					Port:     iacTypes.Int(5439, iacTypes.NewTestMetadata()),
				},
				Encryption: redshift.Encryption{
					Metadata: iacTypes.NewTestMetadata(),
					Enabled:  iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					KMSKeyID: iacTypes.String("", iacTypes.NewTestMetadata()),
				},
				SubnetGroupName: iacTypes.String("", iacTypes.NewTestMetadata()),
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
				Metadata:    iacTypes.NewTestMetadata(),
				Description: iacTypes.String("Managed by Terraform", iacTypes.NewTestMetadata()),
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
