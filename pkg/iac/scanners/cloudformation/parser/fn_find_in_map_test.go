package parser

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"testing"
)

func Test_resolve_find_in_map_value(t *testing.T) {

	source := `---
Parameters:
  Environment: 
    Type: String
    Default: production
Mappings:
  CacheNodeTypes:
    production:
      NodeType: cache.t2.large
    test:
      NodeType: cache.t2.small
    dev:
      NodeType: cache.t2.micro
Resources:
    ElasticacheSecurityGroup:
      Type: 'AWS::EC2::SecurityGroup'
      Properties:
        GroupDescription: Elasticache Security Group
        SecurityGroupIngress:
          - IpProtocol: tcp
            FromPort: 11211
            ToPort: 11211
            SourceSecurityGroupName: !Ref InstanceSecurityGroup
    ElasticacheCluster:
      Type: 'AWS::ElastiCache::CacheCluster'
      Properties:    
        Engine: memcached
        CacheNodeType: !FindInMap [ CacheNodeTypes, production, NodeType ]
        NumCacheNodes: '1'
        VpcSecurityGroupIds:
          - !GetAtt 
            - ElasticacheSecurityGroup
            - GroupId
`
	ctx := createTestFileContext(t, source)
	require.NotNil(t, ctx)

	testRes := ctx.GetResourceByLogicalID("ElasticacheCluster")
	assert.NotNil(t, testRes)

	nodeTypeProp := testRes.GetStringProperty("CacheNodeType", "")
	assert.Equal(t, "cache.t2.large", nodeTypeProp.Value())
}

func Test_resolve_find_in_map_with_nested_intrinsic_value(t *testing.T) {

	source := `---
Parameters:
  Environment: 
    Type: String
    Default: dev
Mappings:
  CacheNodeTypes:
    production:
      NodeType: cache.t2.large
    test:
      NodeType: cache.t2.small
    dev:
      NodeType: cache.t2.micro
Resources:
    ElasticacheSecurityGroup:
      Type: 'AWS::EC2::SecurityGroup'
      Properties:
        GroupDescription: Elasticache Security Group
        SecurityGroupIngress:
          - IpProtocol: tcp
            FromPort: 11211
            ToPort: 11211
            SourceSecurityGroupName: !Ref InstanceSecurityGroup
    ElasticacheCluster:
      Type: 'AWS::ElastiCache::CacheCluster'
      Properties:    
        Engine: memcached
        CacheNodeType: !FindInMap [ CacheNodeTypes, !Ref Environment, NodeType ]
        NumCacheNodes: '1'
        VpcSecurityGroupIds:
          - !GetAtt 
            - ElasticacheSecurityGroup
            - GroupId
`
	ctx := createTestFileContext(t, source)
	require.NotNil(t, ctx)

	testRes := ctx.GetResourceByLogicalID("ElasticacheCluster")
	assert.NotNil(t, testRes)

	nodeTypeProp := testRes.GetStringProperty("CacheNodeType", "")
	assert.Equal(t, "cache.t2.micro", nodeTypeProp.Value())
}
