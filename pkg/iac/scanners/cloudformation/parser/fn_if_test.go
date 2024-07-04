package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_resolve_if_value(t *testing.T) {

	property := &Property{
		ctx:  &FileContext{},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1, "", nil),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::If": {
					Inner: PropertyInner{
						Type: cftypes.List,
						Value: []*Property{
							{
								Inner: PropertyInner{
									Type:  cftypes.Bool,
									Value: true,
								},
							},
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

	resolvedProperty, success := ResolveIntrinsicFunc(property)
	require.True(t, success)

	assert.Equal(t, "foo", resolvedProperty.String())
}
