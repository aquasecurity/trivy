package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_resolve_or_value(t *testing.T) {
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

	property2 := &Property{
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
	orProperty := &Property{
		ctx:  &FileContext{},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1, "", nil),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Or": {
					Inner: PropertyInner{
						Type: cftypes.List,
						Value: []*Property{
							property1,
							property2,
						},
					},
				},
			},
		},
	}

	resolvedProperty, success := ResolveIntrinsicFunc(orProperty)
	require.True(t, success)

	assert.True(t, resolvedProperty.IsTrue())
}

func Test_resolve_or_value_when_neither_true(t *testing.T) {
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

	property2 := &Property{
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
									Value: "bar",
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
	orProperty := &Property{
		ctx:  &FileContext{},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1, "", nil),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Or": {
					Inner: PropertyInner{
						Type: cftypes.List,
						Value: []*Property{
							property1,
							property2,
						},
					},
				},
			},
		},
	}

	resolvedProperty, success := ResolveIntrinsicFunc(orProperty)
	require.True(t, success)

	assert.False(t, resolvedProperty.IsTrue())
}
