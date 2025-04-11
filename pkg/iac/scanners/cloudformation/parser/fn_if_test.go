package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func Test_resolve_if_value(t *testing.T) {

	property := &Property{
		name: "BucketName",
		Type: cftypes.Map,
		Value: map[string]*Property{
			"Fn::If": {
				Type: cftypes.List,
				Value: []*Property{
					{
						Type:  cftypes.Bool,
						Value: true,
					},
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

	assert.Equal(t, "foo", resolvedProperty.String())
}
