package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func Test_resolve_join_value(t *testing.T) {
	property := &Property{
		name: "BucketName",
		Type: cftypes.Map,
		Value: map[string]*Property{
			"Fn::Join": {
				Type: cftypes.List,
				Value: []*Property{
					{
						Type:  cftypes.String,
						Value: "::",
					},
					{
						Type: cftypes.List,
						Value: []*Property{
							{
								Type:  cftypes.String,
								Value: "s3",
							},
							{
								Type:  cftypes.String,
								Value: "part1",
							},
							{
								Type:  cftypes.String,
								Value: "part2",
							},
						},
					},
				},
			},
		},
	}
	resolvedProperty, success := ResolveIntrinsicFunc(property)
	require.True(t, success)

	assert.Equal(t, "s3::part1::part2", resolvedProperty.AsString())
}

func Test_resolve_join_value_with_reference(t *testing.T) {
	property := &Property{
		ctx: &FileContext{
			Parameters: map[string]*Parameter{
				"Environment": {
					inner: parameterInner{
						Type:    "string",
						Default: "staging",
					},
				},
			},
		},
		name: "EnvironmentBucket",
		Type: cftypes.Map,
		Value: map[string]*Property{
			"Fn::Join": {
				Type: cftypes.List,
				Value: []*Property{
					{
						Type:  cftypes.String,
						Value: "::",
					},
					{
						Type: cftypes.List,
						Value: []*Property{
							{
								Type:  cftypes.String,
								Value: "s3",
							},
							{
								Type:  cftypes.String,
								Value: "part1",
							},
							{
								ctx: &FileContext{
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
			},
		},
	}
	resolvedProperty, success := ResolveIntrinsicFunc(property)
	require.True(t, success)

	assert.Equal(t, "s3::part1::staging", resolvedProperty.AsString())
}
