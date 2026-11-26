package parser

import (
	"os"
	"testing"
	"testing/fstest"

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

func TestParseTemplate_NodeRef(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantResource string
		wantTag      string
	}{
		{
			name:         "resources as array",
			input:        `{"resources": [{"tags": {"2024": "x"}}]}`,
			wantResource: "resources[0]",
			wantTag:      "resources[0].tags.2024",
		},
		{
			name:         "resources as object with numeric name",
			input:        `{"resources": {"1": {"tags": {"2024": "x"}}}}`,
			wantResource: "resources.1",
			wantTag:      "resources.1.tags.2024",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"template.json": &fstest.MapFile{Data: []byte(tt.input)},
			}
			template, err := ParseTemplate(fsys, "template.json")
			require.NoError(t, err)
			require.Len(t, template.Resources, 1)

			res := template.Resources[0]
			assert.Equal(t, tt.wantResource, res.Metadata.Reference())
			assert.Equal(t, tt.wantTag, res.Tags.GetMapValue("2024").GetMetadata().Reference())
		})
	}
}
