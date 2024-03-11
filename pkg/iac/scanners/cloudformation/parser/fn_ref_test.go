package parser

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
	"github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_resolve_referenced_value(t *testing.T) {

	property := &Property{
		ctx: &FileContext{
			filepath: "",
			Parameters: map[string]*Parameter{
				"BucketName": {
					inner: parameterInner{
						Type:    "string",
						Default: "someBucketName",
					},
				},
			},
		},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1, "", nil),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Ref": {
					Inner: PropertyInner{
						Type:  cftypes.String,
						Value: "BucketName",
					},
				},
			},
		},
	}

	resolvedProperty, success := ResolveIntrinsicFunc(property)
	require.True(t, success)

	assert.Equal(t, "someBucketName", resolvedProperty.AsString())
}

func Test_property_value_correct_when_not_reference(t *testing.T) {

	property := &Property{
		ctx: &FileContext{
			filepath: "",
		},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1, "", nil),
		Inner: PropertyInner{
			Type:  cftypes.String,
			Value: "someBucketName",
		},
	}

	// should fail when trying to resolve function that is not in fact a function
	resolvedProperty, success := ResolveIntrinsicFunc(property)
	require.False(t, success)

	assert.Equal(t, "someBucketName", resolvedProperty.AsString())
}

func Test_resolve_ref_with_pseudo_value(t *testing.T) {
	source := `---
Resources:
  TestInstance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: "ami-79fd7eee"
      KeyName: !Join [":", ["aws", !Ref AWS::Region, "key" ]]
`
	ctx := createTestFileContext(t, source)
	require.NotNil(t, ctx)

	testRes := ctx.GetResourceByLogicalID("TestInstance")
	require.NotNil(t, testRes)

	keyNameProp := testRes.GetProperty("KeyName")
	require.NotNil(t, keyNameProp)

	assert.Equal(t, "aws:eu-west-1:key", keyNameProp.AsString())
}
