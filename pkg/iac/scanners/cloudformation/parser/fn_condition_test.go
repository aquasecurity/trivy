package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func Test_resolve_condition_value(t *testing.T) {
	fctx := new(FileContext)
	fctx.Conditions = map[string]Property{
		"SomeCondition": {
			ctx:  fctx,
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Equals": {
					ctx:  fctx,
					Type: cftypes.List,
					Value: []*Property{
						{
							Type:  cftypes.String,
							Value: "some val",
						},
						{
							Type:  cftypes.String,
							Value: "some val",
						},
					},
				},
			},
		},
		"EnableVersioning": {
			ctx:  fctx,
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Condition": {
					Type:  cftypes.String,
					Value: "SomeCondition",
				},
			},
		},
	}

	property := &Property{
		ctx:  fctx,
		Type: cftypes.Map,
		Value: map[string]*Property{
			"Fn::If": {
				ctx:  fctx,
				Type: cftypes.List,
				Value: []*Property{
					{
						Type:  cftypes.String,
						Value: "EnableVersioning",
					},
					{
						Type:  cftypes.String,
						Value: "Enabled",
					},
					{
						Type:  cftypes.String,
						Value: "Suspended",
					},
				},
			},
		},
	}

	resolvedProperty, success := ResolveIntrinsicFunc(property)
	require.True(t, success)

	assert.Equal(t, "Enabled", resolvedProperty.AsString())
}
