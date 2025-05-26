package parser

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func Test_ResolveLength_WhenPropIsArray(t *testing.T) {
	prop := &Property{
		Type: cftypes.Map,
		Value: map[string]*Property{
			"Fn::Length": {
				Type: cftypes.List,
				Value: []*Property{
					{
						Type:  cftypes.Int,
						Value: 1,
					},
					{
						Type:  cftypes.String,
						Value: "IntParameter",
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
		Type: cftypes.Map,
		Value: map[string]*Property{
			"Fn::Length": {
				Type: cftypes.Map,
				Value: map[string]*Property{
					"Fn::Split": {
						Type: cftypes.List,
						Value: []*Property{
							{
								Type:  cftypes.String,
								Value: "|",
							},
							{
								ctx:  fctx,
								Type: cftypes.Map,
								Value: map[string]*Property{
									"Ref": {
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
	}
	resolved, ok := ResolveIntrinsicFunc(prop)
	require.True(t, ok)
	require.True(t, resolved.IsInt())
	require.Equal(t, 4, resolved.AsInt())
}
