package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_resolve_select_value(t *testing.T) {

	source := `---
Parameters:
    EngineIndex:
      Type: Integer
      Default: 1
Resources:
    ElasticacheCluster:
      Type: 'AWS::ElastiCache::CacheCluster'
      Properties:    
        Engine: !Select [ !Ref EngineIndex, [memcached, redis ]]
        CacheNodeType: cache.t2.micro
        NumCacheNodes: '1'
`
	ctx := createTestFileContext(t, source)
	require.NotNil(t, ctx)

	testRes := ctx.GetResourceByLogicalID("ElasticacheCluster")
	assert.NotNil(t, testRes)

	engineProp := testRes.GetProperty("Engine")
	require.True(t, engineProp.IsNotNil())
	require.True(t, engineProp.IsString())

	require.Equal(t, "redis", engineProp.AsString())
}

func Test_SelectPseudoListParam(t *testing.T) {
	src := `---
Resources:
  myASGrpOne:
    Type: AWS::AutoScaling::AutoScalingGroup
    Version: "2009-05-15"
    Properties:
      AvailabilityZones:
        - "us-east-1a"
      LaunchConfigurationName:
        Ref: MyLaunchConfiguration
      MinSize: "0"
      MaxSize: "0"
      NotificationConfigurations:
        - TopicARN:
            Fn::Select:
              - "1"
              - Ref: AWS::NotificationARNs
      NotificationTypes:
        - autoscaling:EC2_INSTANCE_LAUNCH
        - autoscaling:EC2_INSTANCE_LAUNCH_ERROR

`

	ctx := createTestFileContext(t, src)
	require.NotNil(t, ctx)

	resource := ctx.GetResourceByLogicalID("myASGrpOne")
	require.NotNil(t, resource)

	notification := resource.GetProperty("NotificationConfigurations")
	require.True(t, notification.IsNotNil())
	require.True(t, notification.IsList())
	first := notification.AsList()[0]
	require.True(t, first.IsMap())
	topic, ok := first.AsMap()["TopicARN"]
	require.True(t, ok)
	require.Equal(t, "notification::arn::2", topic.AsString())

}
