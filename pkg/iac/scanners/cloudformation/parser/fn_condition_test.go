package parser

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_resolve_condition_value(t *testing.T) {

	fctx := new(FileContext)
	fctx.Conditions = map[string]Property{
		"SomeCondition": {
			ctx: fctx,
			Inner: PropertyInner{
				Type: cftypes.Map,
				Value: map[string]*Property{
					"Fn::Equals": {
						ctx: fctx,
						Inner: PropertyInner{
							Type: cftypes.List,
							Value: []*Property{
								{
									Inner: PropertyInner{
										Type:  cftypes.String,
										Value: "some val",
									},
								},
								{
									Inner: PropertyInner{
										Type:  cftypes.String,
										Value: "some val",
									},
								},
							},
						},
					},
				},
			},
		},
		"EnableVersioning": {
			ctx: fctx,
			Inner: PropertyInner{
				Type: cftypes.Map,
				Value: map[string]*Property{
					"Condition": {
						Inner: PropertyInner{
							Type:  cftypes.String,
							Value: "SomeCondition",
						},
					},
				},
			},
		},
	}

	property := &Property{
		ctx: fctx,
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::If": {
					ctx: fctx,
					Inner: PropertyInner{
						Type: cftypes.List,
						Value: []*Property{
							{
								Inner: PropertyInner{
									Type:  cftypes.String,
									Value: "EnableVersioning",
								},
							},
							{
								Inner: PropertyInner{
									Type:  cftypes.String,
									Value: "Enabled",
								},
							},
							{
								Inner: PropertyInner{
									Type:  cftypes.String,
									Value: "Suspended",
								},
							},
						},
					},
				},
			},
		},
	}

	resolvedProperty, success := ResolveIntrinsicFunc(property)
	require.True(t, success)

	assert.Equal(t, "Enabled", resolvedProperty.AsString())
}
