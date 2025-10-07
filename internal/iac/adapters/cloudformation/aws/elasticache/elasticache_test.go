package elasticache

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elasticache"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected elasticache.ElastiCache
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  ElasticacheCluster:
    Type: 'AWS::ElastiCache::CacheCluster'
    Properties:    
      Engine: memcached
      CacheNodeType: cache.t2.micro
      SnapshotRetentionLimit: 5
  myReplicationGroup:
    Type: 'AWS::ElastiCache::ReplicationGroup'
    Properties:
      TransitEncryptionEnabled: true
      AtRestEncryptionEnabled: true
  mySecGroup:
    Type: AWS::ElastiCache::SecurityGroup
    Properties:
      Description: test
`,
			expected: elasticache.ElastiCache{
				Clusters: []elasticache.Cluster{
					{
						Engine:                 types.StringTest("memcached"),
						NodeType:               types.StringTest("cache.t2.micro"),
						SnapshotRetentionLimit: types.IntTest(5),
					},
				},
				ReplicationGroups: []elasticache.ReplicationGroup{
					{
						TransitEncryptionEnabled: types.BoolTest(true),
						AtRestEncryptionEnabled:  types.BoolTest(true),
					},
				},
				SecurityGroups: []elasticache.SecurityGroup{
					{
						Description: types.StringTest("test"),
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  ElasticacheCluster:
    Type: 'AWS::ElastiCache::CacheCluster'
  myReplicationGroup:
    Type: 'AWS::ElastiCache::ReplicationGroup'
  mySecGroup:
    Type: AWS::ElastiCache::SecurityGroup
  `,
			expected: elasticache.ElastiCache{
				Clusters:          []elasticache.Cluster{{}},
				ReplicationGroups: []elasticache.ReplicationGroup{{}},
				SecurityGroups:    []elasticache.SecurityGroup{{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
