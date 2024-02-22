package parser

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
	"github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_resolve_not_value(t *testing.T) {
	property1 := &Property{
		ctx:  &FileContext{},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1, "", nil),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Equals": {
					Inner: PropertyInner{
						Type: cftypes.List,
						Value: []*Property{
							{
								Inner: PropertyInner{
									Type:  cftypes.String,
									Value: "foo",
								},
							},
							{
								Inner: PropertyInner{
									Type:  cftypes.String,
									Value: "bar",
								},
							},
						},
					},
				},
			},
		},
	}

	notProperty := &Property{
		ctx:  &FileContext{},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1, "", nil),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Not": {
					Inner: PropertyInner{
						Type: cftypes.List,
						Value: []*Property{
							property1,
						},
					},
				},
			},
		},
	}

	resolvedProperty, success := ResolveIntrinsicFunc(notProperty)
	require.True(t, success)

	assert.True(t, resolvedProperty.IsTrue())
}

func Test_resolve_not_value_when_true(t *testing.T) {
	property1 := &Property{
		ctx:  &FileContext{},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1, "", nil),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Equals": {
					Inner: PropertyInner{
						Type: cftypes.List,
						Value: []*Property{
							{
								Inner: PropertyInner{
									Type:  cftypes.String,
									Value: "foo",
								},
							},
							{
								Inner: PropertyInner{
									Type:  cftypes.String,
									Value: "foo",
								},
							},
						},
					},
				},
			},
		},
	}

	notProperty := &Property{
		ctx:  &FileContext{},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1, "", nil),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Not": {
					Inner: PropertyInner{
						Type: cftypes.List,
						Value: []*Property{
							property1,
						},
					},
				},
			},
		},
	}

	resolvedProperty, success := ResolveIntrinsicFunc(notProperty)
	require.True(t, success)

	assert.False(t, resolvedProperty.IsTrue())
}
