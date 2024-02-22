package elasticache

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elasticache"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptCluster(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  elasticache.Cluster
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_elasticache_cluster" "example" {
				cluster_id           = "cluster-example"
				engine               = "redis"
				node_type            = "cache.m4.large"
				num_cache_nodes      = 1
				parameter_group_name = "default.redis3.2"
				engine_version       = "3.2.10"
				port                 = 6379
			
				snapshot_retention_limit = 5
			}
`,
			expected: elasticache.Cluster{
				Metadata:               iacTypes.NewTestMetadata(),
				Engine:                 iacTypes.String("redis", iacTypes.NewTestMetadata()),
				NodeType:               iacTypes.String("cache.m4.large", iacTypes.NewTestMetadata()),
				SnapshotRetentionLimit: iacTypes.Int(5, iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_elasticache_cluster" "example" {
			}`,
			expected: elasticache.Cluster{
				Metadata:               iacTypes.NewTestMetadata(),
				Engine:                 iacTypes.String("", iacTypes.NewTestMetadata()),
				NodeType:               iacTypes.String("", iacTypes.NewTestMetadata()),
				SnapshotRetentionLimit: iacTypes.Int(0, iacTypes.NewTestMetadata()),
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

func Test_adaptReplicationGroup(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  elasticache.ReplicationGroup
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_elasticache_replication_group" "example" {
				replication_group_id = "foo"
				replication_group_description = "my foo cluster"
				transit_encryption_enabled = true
				at_rest_encryption_enabled = true
		}
`,
			expected: elasticache.ReplicationGroup{
				Metadata:                 iacTypes.NewTestMetadata(),
				TransitEncryptionEnabled: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
				AtRestEncryptionEnabled:  iacTypes.Bool(true, iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_elasticache_replication_group" "example" {
		}
`,
			expected: elasticache.ReplicationGroup{
				Metadata:                 iacTypes.NewTestMetadata(),
				TransitEncryptionEnabled: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
				AtRestEncryptionEnabled:  iacTypes.Bool(false, iacTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptReplicationGroup(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptSecurityGroup(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  elasticache.SecurityGroup
	}{
		{
			name: "description provided",
			terraform: `
			resource "aws_security_group" "bar" {
				name = "security-group"
			}
			
			resource "aws_elasticache_security_group" "example" {
				name = "elasticache-security-group"
				security_group_names = [aws_security_group.bar.name]
				description = "something"
			}			
`,
			expected: elasticache.SecurityGroup{
				Metadata:    iacTypes.NewTestMetadata(),
				Description: iacTypes.String("something", iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "missing description",
			terraform: `
			resource "aws_security_group" "bar" {
				name = "security-group"
			}
			
			resource "aws_elasticache_security_group" "example" {
				security_group_names = [aws_security_group.bar.name]
			}
`,
			expected: elasticache.SecurityGroup{
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
	resource "aws_elasticache_cluster" "example" {
		cluster_id           = "cluster-example"
		engine               = "redis"
		node_type            = "cache.m4.large"
		num_cache_nodes      = 1
		parameter_group_name = "default.redis3.2"
		engine_version       = "3.2.10"
		port                 = 6379
	
		snapshot_retention_limit = 5
	}

	resource "aws_elasticache_replication_group" "example" {
		replication_group_id = "foo"
		replication_group_description = "my foo cluster"
		transit_encryption_enabled = true
		at_rest_encryption_enabled = true
	}

	resource "aws_security_group" "bar" {
		name = "security-group"
	}

	resource "aws_elasticache_security_group" "example" {
		name = "elasticache-security-group"
		security_group_names = [aws_security_group.bar.name]
		description = "something"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	require.Len(t, adapted.ReplicationGroups, 1)
	require.Len(t, adapted.SecurityGroups, 1)

	cluster := adapted.Clusters[0]
	replicationGroup := adapted.ReplicationGroups[0]
	securityGroup := adapted.SecurityGroups[0]

	assert.Equal(t, 2, cluster.Metadata.Range().GetStartLine())
	assert.Equal(t, 12, cluster.Metadata.Range().GetEndLine())

	assert.Equal(t, 4, cluster.Engine.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, cluster.Engine.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, cluster.NodeType.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, cluster.NodeType.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, cluster.SnapshotRetentionLimit.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, cluster.SnapshotRetentionLimit.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 14, replicationGroup.Metadata.Range().GetStartLine())
	assert.Equal(t, 19, replicationGroup.Metadata.Range().GetEndLine())

	assert.Equal(t, 17, replicationGroup.TransitEncryptionEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 17, replicationGroup.TransitEncryptionEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 18, replicationGroup.AtRestEncryptionEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 18, replicationGroup.AtRestEncryptionEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 25, securityGroup.Metadata.Range().GetStartLine())
	assert.Equal(t, 29, securityGroup.Metadata.Range().GetEndLine())

	assert.Equal(t, 28, securityGroup.Description.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 28, securityGroup.Description.GetMetadata().Range().GetEndLine())

}
