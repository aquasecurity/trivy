package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

/*
	Fn::Split: ["::", "s3::bucket::to::split"]

*/

func Test_resolve_split_value(t *testing.T) {

	property := &Property{
		name: "BucketName",
		Type: cftypes.Map,
		Value: map[string]*Property{
			"Fn::Split": {
				Type: cftypes.List,
				Value: []*Property{
					{
						Type:  cftypes.String,
						Value: "::",
					},
					{
						Type:  cftypes.String,
						Value: "s3::bucket::to::split",
					},
				},
			},
		},
	}

	resolvedProperty, success := ResolveIntrinsicFunc(property)
	require.True(t, success)
	assert.True(t, resolvedProperty.IsNotNil())
	assert.True(t, resolvedProperty.IsList())
	listContents := resolvedProperty.AsList()
	assert.Len(t, listContents, 4)

}
