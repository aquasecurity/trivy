package parser

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"testing"
)

func Test_resolve_get_attr_value(t *testing.T) {

	source := `---
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
        CacheNodeType: cache.t2.micro
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

	sgProp := testRes.GetProperty("VpcSecurityGroupIds")
	require.True(t, sgProp.IsNotNil())
	require.True(t, sgProp.IsList())

	for _, property := range sgProp.AsList() {
		resolved, success := ResolveIntrinsicFunc(property)
		require.True(t, success)
		assert.True(t, resolved.IsNotNil())
	}

}
