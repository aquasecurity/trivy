package parser

import (
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_FindInMap(t *testing.T) {
	source := `---
Parameters:
  Environment: 
    Type: String
    Default: dev
Mappings:
  CacheNodeTypes:
    production:
      NodeType: cache.t2.large
      CacheSecurityGroupNames: [ "sg-1", "sg-2" ]
    test:
      NodeType: cache.t2.small
      CacheSecurityGroupNames: [ "sg-3" ]
    dev:
      NodeType: cache.t2.micro
      CacheSecurityGroupNames: [ "sg-4" ]
Resources:
  ElasticacheCluster:
    Type: 'AWS::ElastiCache::CacheCluster'
    Properties:    
      Engine: memcached
      CacheNodeType: !FindInMap [ CacheNodeTypes, !Ref Environment, NodeType ]
      NumCacheNodes: '1'

  ElasticacheClusterWithDefault:
    Type: 'AWS::ElastiCache::CacheCluster'
    Properties:
      Engine: memcached
      CacheNodeType: !FindInMap [ CacheNodeTypes, staging, NodeType, DefaultValue: cache.t2.medium ]
      NumCacheNodes: '1'

  ElasticacheClusterList:
    Type: 'AWS::ElastiCache::CacheCluster'
    Properties:
      Engine: memcached
      CacheSecurityGroupNames: !FindInMap [ CacheNodeTypes, production, CacheSecurityGroupNames ]
      NumCacheNodes: '1'
`

	ctx := createTestFileContext(t, source)
	require.NotNil(t, ctx)

	cluster := ctx.GetResourceByLogicalID("ElasticacheCluster")
	require.NotNil(t, cluster)
	nodeTypeProp := cluster.GetStringProperty("CacheNodeType", "")
	assert.Equal(t, "cache.t2.micro", nodeTypeProp.Value())

	clusterDefault := ctx.GetResourceByLogicalID("ElasticacheClusterWithDefault")
	require.NotNil(t, clusterDefault)
	nodeTypePropDefault := clusterDefault.GetStringProperty("CacheNodeType", "")
	assert.Equal(t, "cache.t2.medium", nodeTypePropDefault.Value())

	clusterList := ctx.GetResourceByLogicalID("ElasticacheClusterList")
	require.NotNil(t, clusterList)
	sgNamesProp := clusterList.GetProperty("CacheSecurityGroupNames").AsList()
	groupNames := lo.Map(sgNamesProp, func(prop *Property, _ int) any {
		return prop.AsString()
	})
	assert.ElementsMatch(t, []any{"sg-1", "sg-2"}, groupNames)
}

func Test_InferType(t *testing.T) {
	source := `---
Mappings:
  ApiDB:
     MultiAZ:
        development: False
Resources:
  ApiDB:
    Type: AWS::RDS::DBInstance
    Properties:
      MultiAZ: !FindInMap [ApiDB, MultiAZ, development]
`

	ctx := createTestFileContext(t, source)
	require.NotNil(t, ctx)

	testRes := ctx.GetResourceByLogicalID("ApiDB")
	require.NotNil(t, testRes)

	nodeTypeProp := testRes.GetBoolProperty("MultiAZ")
	assert.False(t, nodeTypeProp.Value())
}
