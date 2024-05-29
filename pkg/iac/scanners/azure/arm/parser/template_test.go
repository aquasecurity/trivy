package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	types2 "github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure/arm/parser/armjson"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_JSONUnmarshal(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "example.json"))
	require.NoError(t, err)
	var target Template
	metadata := types.NewTestMetadata()
	require.NoError(t, armjson.Unmarshal(data, &target, &metadata))
	assert.Equal(t,
		"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
		target.Schema.AsString(),
	)
	require.Len(t, target.Schema.Comments, 2)
	assert.Equal(t, " wow this is a comment", target.Schema.Comments[0])
	assert.Equal(t, " another one", target.Schema.Comments[1])

	assert.Equal(t, "1.0.0.0", target.ContentVersion.Raw())
	require.Len(t, target.ContentVersion.Comments, 1)
	assert.Equal(t, " this version is great", target.ContentVersion.Comments[0])

	require.Contains(t, target.Parameters, "storagePrefix")
	prefix := target.Parameters["storagePrefix"]
	/*
	   "type": "string",
	   "defaultValue": "x",
	   "maxLength": 11,
	   "minLength": 3
	*/
	assert.Equal(t, "string", prefix.Type.Raw())
	assert.Equal(t, types2.KindString, prefix.Type.Kind)
	assert.Equal(t, 8, prefix.Type.Metadata.Range().GetStartLine())
	assert.Equal(t, 8, prefix.Type.Metadata.Range().GetEndLine())

	assert.Equal(t, "x", prefix.DefaultValue.Raw())
	assert.Equal(t, types2.KindString, prefix.DefaultValue.Kind)
	assert.Equal(t, 9, prefix.DefaultValue.Metadata.Range().GetStartLine())
	assert.Equal(t, 9, prefix.DefaultValue.Metadata.Range().GetEndLine())

	assert.Equal(t, int64(11), prefix.MaxLength.Raw())
	assert.Equal(t, types2.KindNumber, prefix.MaxLength.Kind)
	assert.Equal(t, 10, prefix.MaxLength.Metadata.Range().GetStartLine())
	assert.Equal(t, 10, prefix.MaxLength.Metadata.Range().GetEndLine())

	assert.Equal(t, int64(3), prefix.MinLength.Raw())
	assert.Equal(t, types2.KindNumber, prefix.MinLength.Kind)
	assert.Equal(t, 11, prefix.MinLength.Metadata.Range().GetStartLine())
	assert.Equal(t, 11, prefix.MinLength.Metadata.Range().GetEndLine())
}
