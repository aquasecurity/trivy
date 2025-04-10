package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_resolve_equals_value(t *testing.T) {

	property := &Property{
		ctx:  &FileContext{},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1, "", nil),
		Type: cftypes.Map,
		Value: map[string]*Property{
			"Fn::Equals": {
				Type: cftypes.List,
				Value: []*Property{
					{
						Type:  cftypes.String,
						Value: "foo",
					},
					{
						Type:  cftypes.String,
						Value: "foo",
					},
				},
			},
		},
	}

	resolvedProperty, success := ResolveIntrinsicFunc(property)
	require.True(t, success)

	assert.True(t, resolvedProperty.IsTrue())
}

func Test_resolve_equals_value_to_false(t *testing.T) {

	property := &Property{
		ctx:  &FileContext{},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1, "", nil),
		Type: cftypes.Map,
		Value: map[string]*Property{
			"Fn::Equals": {
				Type: cftypes.List,
				Value: []*Property{
					{
						Type:  cftypes.String,
						Value: "foo",
					},
					{
						Type:  cftypes.String,
						Value: "bar",
					},
				},
			},
		},
	}

	resolvedProperty, success := ResolveIntrinsicFunc(property)
	require.True(t, success)

	assert.False(t, resolvedProperty.IsTrue())
}

func Test_resolve_equals_value_to_true_when_boolean(t *testing.T) {

	property := &Property{
		ctx:  &FileContext{},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1, "", nil),
		Type: cftypes.Map,
		Value: map[string]*Property{
			"Fn::Equals": {
				Type: cftypes.List,
				Value: []*Property{
					{
						Type:  cftypes.Bool,
						Value: true,
					},
					{
						Type:  cftypes.Bool,
						Value: true,
					},
				},
			},
		},
	}

	resolvedProperty, success := ResolveIntrinsicFunc(property)
	require.True(t, success)
	assert.True(t, resolvedProperty.IsTrue())
}

func Test_resolve_equals_value_when_one_is_a_reference(t *testing.T) {

	property := &Property{
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1, "", nil),
		Type: cftypes.Map,
		Value: map[string]*Property{
			"Fn::Equals": {
				Type: cftypes.List,
				Value: []*Property{
					{
						Type:  cftypes.String,
						Value: "staging",
					},
					{
						ctx: &FileContext{
							filepath: "",
							Parameters: map[string]*Parameter{
								"Environment": {
									inner: parameterInner{
										Type:    "string",
										Default: "staging",
									},
								},
							},
						},
						Type: cftypes.Map,
						Value: map[string]*Property{
							"Ref": {
								Type:  cftypes.String,
								Value: "Environment",
							},
						},
					},
				},
			},
		},
	}

	resolvedProperty, success := ResolveIntrinsicFunc(property)
	require.True(t, success)

	assert.True(t, resolvedProperty.IsTrue())
}
