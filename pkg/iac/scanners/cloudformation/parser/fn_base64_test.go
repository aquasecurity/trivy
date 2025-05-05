package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func Test_resolve_base64_value(t *testing.T) {
	property := &Property{
		name: "BucketName",
		Type: cftypes.Map,
		Value: map[string]*Property{
			"Fn::Base64": {
				Type:  cftypes.String,
				Value: "HelloWorld",
			},
		},
	}

	resolvedProperty, success := ResolveIntrinsicFunc(property)
	require.True(t, success)

	assert.Equal(t, "SGVsbG9Xb3JsZA==", resolvedProperty.AsString())
}
