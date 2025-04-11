package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func Test_resolve_or_value(t *testing.T) {
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

	property2 := &Property{
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
	orProperty := &Property{
		name: "BucketName",
		Type: cftypes.Map,
		Value: map[string]*Property{
			"Fn::Or": {
				Type: cftypes.List,
				Value: []*Property{
					property1,
					property2,
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

	property2 := &Property{
		name: "BucketName",
		Type: cftypes.Map,
		Value: map[string]*Property{
			"Fn::Equals": {
				Type: cftypes.List,
				Value: []*Property{
					{
						Type:  cftypes.String,
						Value: "bar",
					},
					{
						Type:  cftypes.String,
						Value: "foo",
					},
				},
			},
		},
	}
	orProperty := &Property{
		name: "BucketName",
		Type: cftypes.Map,
		Value: map[string]*Property{
			"Fn::Or": {
				Type: cftypes.List,
				Value: []*Property{
					property1,
					property2,
				},
			},
		},
	}

	resolvedProperty, success := ResolveIntrinsicFunc(orProperty)
	require.True(t, success)

	assert.False(t, resolvedProperty.IsTrue())
}
