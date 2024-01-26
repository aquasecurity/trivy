package redshift

import (
	"fmt"
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/redshift"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/test/testutil"
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
						Metadata:            defsecTypes.NewTestMetadata(),
						ClusterIdentifier:   defsecTypes.String("tf-redshift-cluster", defsecTypes.NewTestMetadata()),
						PubliclyAccessible:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						NumberOfNodes:       defsecTypes.Int(1, defsecTypes.NewTestMetadata()),
						AllowVersionUpgrade: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						EndPoint: redshift.EndPoint{
							Metadata: defsecTypes.NewTestMetadata(),
							Port:     defsecTypes.Int(5440, defsecTypes.NewTestMetadata()),
						},
						Encryption: redshift.Encryption{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							KMSKeyID: defsecTypes.String("aws_kms_key.redshift", defsecTypes.NewTestMetadata()),
						},
						SubnetGroupName: defsecTypes.String("redshift_subnet", defsecTypes.NewTestMetadata()),
					},
				},
				SecurityGroups: []redshift.SecurityGroup{
					{
						Metadata:    defsecTypes.NewTestMetadata(),
						Description: defsecTypes.String("some description", defsecTypes.NewTestMetadata()),
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
				Metadata:            defsecTypes.NewTestMetadata(),
				ClusterIdentifier:   defsecTypes.String("tf-redshift-cluster", defsecTypes.NewTestMetadata()),
				PubliclyAccessible:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				NumberOfNodes:       defsecTypes.Int(1, defsecTypes.NewTestMetadata()),
				AllowVersionUpgrade: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				EndPoint: redshift.EndPoint{
					Metadata: defsecTypes.NewTestMetadata(),
					Port:     defsecTypes.Int(5440, defsecTypes.NewTestMetadata()),
				},
				Encryption: redshift.Encryption{
					Metadata: defsecTypes.NewTestMetadata(),
					Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					KMSKeyID: defsecTypes.String("key-id", defsecTypes.NewTestMetadata()),
				},
				SubnetGroupName: defsecTypes.String("redshift_subnet", defsecTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `			
			resource "aws_redshift_cluster" "example" {
			}
`,
			expected: redshift.Cluster{
				Metadata:            defsecTypes.NewTestMetadata(),
				ClusterIdentifier:   defsecTypes.String("", defsecTypes.NewTestMetadata()),
				PubliclyAccessible:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				NumberOfNodes:       defsecTypes.Int(1, defsecTypes.NewTestMetadata()),
				AllowVersionUpgrade: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				EndPoint: redshift.EndPoint{
					Metadata: defsecTypes.NewTestMetadata(),
					Port:     defsecTypes.Int(5439, defsecTypes.NewTestMetadata()),
				},
				Encryption: redshift.Encryption{
					Metadata: defsecTypes.NewTestMetadata(),
					Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					KMSKeyID: defsecTypes.String("", defsecTypes.NewTestMetadata()),
				},
				SubnetGroupName: defsecTypes.String("", defsecTypes.NewTestMetadata()),
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
				Metadata:    defsecTypes.NewTestMetadata(),
				Description: defsecTypes.String("Managed by Terraform", defsecTypes.NewTestMetadata()),
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
