package parser

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
)

func Test_JSONUnmarshal(t *testing.T) {
	target, err := ParseTemplate(os.DirFS("testdata"), "example.json")
	require.NoError(t, err)

	assert.Equal(t,
		"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
		target.Schema.AsString(),
	)

	assert.Equal(t, "1.0.0.0", target.ContentVersion.Raw())

	require.Contains(t, target.Parameters, "storagePrefix")
	prefix := target.Parameters["storagePrefix"]
	/*
	   "type": "string",
	   "defaultValue": "x",
	   "maxLength": 11,
	   "minLength": 3
	*/
	assert.Equal(t, "string", prefix.Type.Raw())
	assert.Equal(t, azure.KindString, prefix.Type.Kind)
	assert.Equal(t, 8, prefix.Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 8, prefix.Type.GetMetadata().Range().GetEndLine())

	assert.Equal(t, "x", prefix.DefaultValue.Raw())
	assert.Equal(t, azure.KindString, prefix.DefaultValue.Kind)
	assert.Equal(t, 9, prefix.DefaultValue.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, prefix.DefaultValue.GetMetadata().Range().GetEndLine())

	assert.Equal(t, int64(11), prefix.MaxLength.Raw())
	assert.Equal(t, azure.KindNumber, prefix.MaxLength.Kind)
	assert.Equal(t, 10, prefix.MaxLength.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, prefix.MaxLength.GetMetadata().Range().GetEndLine())

	assert.Equal(t, int64(3), prefix.MinLength.Raw())
	assert.Equal(t, azure.KindNumber, prefix.MinLength.Kind)
	assert.Equal(t, 11, prefix.MinLength.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, prefix.MinLength.GetMetadata().Range().GetEndLine())
}
