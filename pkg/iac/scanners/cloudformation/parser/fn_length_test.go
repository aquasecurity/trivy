package parser

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
	"github.com/stretchr/testify/require"
)

func Test_ResolveLength_WhenPropIsArray(t *testing.T) {
	prop := &Property{
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Length": {
					Inner: PropertyInner{
						Type: cftypes.List,
						Value: []*Property{
							{
								Inner: PropertyInner{
									Type:  cftypes.Int,
									Value: 1,
								},
							},
							{
								Inner: PropertyInner{
									Type:  cftypes.String,
									Value: "IntParameter",
								},
							},
						},
					},
				},
			},
		},
	}
	resolved, ok := ResolveIntrinsicFunc(prop)
	require.True(t, ok)
	require.True(t, resolved.IsInt())
	require.Equal(t, 2, resolved.AsInt())
}

func Test_ResolveLength_WhenPropIsIntrinsicFunction(t *testing.T) {
	fctx := &FileContext{
		Parameters: map[string]*Parameter{
			"SomeParameter": {
				inner: parameterInner{
					Type:    "string",
					Default: "a|b|c|d",
				},
			},
		},
	}
	prop := &Property{
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Length": {
					Inner: PropertyInner{
						Type: cftypes.Map,
						Value: map[string]*Property{
							"Fn::Split": {
								Inner: PropertyInner{
									Type: cftypes.List,
									Value: []*Property{
										{
											Inner: PropertyInner{
												Type:  cftypes.String,
												Value: "|",
											},
										},
										{
											ctx: fctx,
											Inner: PropertyInner{
												Type: cftypes.Map,
												Value: map[string]*Property{
													"Ref": {
														Inner: PropertyInner{
															Type:  cftypes.String,
															Value: "SomeParameter",
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	resolved, ok := ResolveIntrinsicFunc(prop)
	require.True(t, ok)
	require.True(t, resolved.IsInt())
	require.Equal(t, 4, resolved.AsInt())
}
