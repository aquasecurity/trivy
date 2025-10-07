package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func Test_resolve_not_value(t *testing.T) {
	property1 := &Property{
		name: "BucketName",
		Type: cftypes.Map,
		Value: map[string]*Property{
			"Fn::Equals": {
				Type: cftypes.List,
				Value: []*Property{
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

	notProperty := &Property{
		name: "BucketName",
		Type: cftypes.Map,
		Value: map[string]*Property{
			"Fn::Not": {
				Type: cftypes.List,
				Value: []*Property{
					property1,
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
		name: "BucketName",
		Type: cftypes.Map,
		Value: map[string]*Property{
			"Fn::Equals": {
				Type: cftypes.List,
				Value: []*Property{
					{
						Type:  cftypes.String,
						Value: "foo",
					},
					{
						Type:  cftypes.String,
						Value: "foo",
					},
				},
			},
		},
	}

	notProperty := &Property{
		name: "BucketName",
		Type: cftypes.Map,
		Value: map[string]*Property{
			"Fn::Not": {
				Type: cftypes.List,
				Value: []*Property{
					property1,
				},
			},
		},
	}

	resolvedProperty, success := ResolveIntrinsicFunc(notProperty)
	require.True(t, success)

	assert.False(t, resolvedProperty.IsTrue())
}
