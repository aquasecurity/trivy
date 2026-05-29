package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)


func mustParseYAML(t *testing.T, source string) FileContexts {
	t.Helper()
	files, err := parseFile(t, source, "cf.yaml")
	require.NoError(t, err)
	return files
}

func Test_Property_AsBoolValue_StringAndIntInference(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{name: "bool true", value: "true", expected: true},
		{name: "bool false", value: "false", expected: false},
		{name: "string true", value: `"true"`, expected: true},
		{name: "string yes", value: `"yes"`, expected: true},
		{name: "string 1", value: `"1"`, expected: true},
		{name: "string TRUE uppercase", value: `"TRUE"`, expected: true},
		{name: "string false", value: `"false"`, expected: false},
		{name: "string no", value: `"no"`, expected: false},
		{name: "string 0", value: `"0"`, expected: false},
		{name: "int 1", value: "1", expected: true},
		{name: "int 0", value: "0", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := `---
Resources:
  MyResource:
    Type: AWS::S3::Bucket
    Properties:
      Flag: ` + tt.value

			prop := mustParseYAML(t, source)[0].Resources["MyResource"].GetProperty("Flag")
			assert.Equal(t, tt.expected, prop.AsBoolValue().IsTrue())
		})
	}
}

func Test_Resource_GetBoolProperty_MissingKeyUsesDefault(t *testing.T) {
	source := `---
Resources:
  MyResource:
    Type: AWS::S3::Bucket
    Properties:
      Other: value`

	resource := mustParseYAML(t, source)[0].Resources["MyResource"]

	assert.False(t, resource.GetBoolProperty("Missing").IsTrue())
	assert.True(t, resource.GetBoolProperty("Missing", true).IsTrue())
}



func Test_Resource_GetProperty_MetadataPropagation(t *testing.T) {
	source := `---
Resources:
  MyResource:
    Type: AWS::S3::Bucket
    Properties:
      Name: myvalue
      Nested:
        DeepKey: deepvalue`

	resource := mustParseYAML(t, source)[0].Resources["MyResource"]

	existing := resource.GetStringProperty("Name")
	assert.Equal(t, "myvalue", existing.Value())
	assert.Equal(t, resource.GetProperty("Name").Metadata().Range(), existing.GetMetadata().Range())

	deep := resource.GetStringProperty("Nested.DeepKey")
	assert.Equal(t, "deepvalue", deep.Value())
	assert.Equal(t, resource.GetProperty("Nested.DeepKey").Metadata().Range(), deep.GetMetadata().Range())

	missing := resource.GetStringProperty("Missing")
	assert.Equal(t, "", missing.Value())
	assert.Equal(t, resource.Range(), missing.GetMetadata().Range())

	nestedMissing := resource.GetStringProperty("Nested.Missing")
	assert.Equal(t, "", nestedMissing.Value())
	assert.Equal(t, resource.GetProperty("Nested").Metadata().Range(), nestedMissing.GetMetadata().Range())
}
