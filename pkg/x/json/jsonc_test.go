package json_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

func TestToRFC8259(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no comments",
			input: `{"a": 1, "b": 2}`,
			want:  `{"a": 1, "b": 2}`,
		},
		{
			name:  "single-line comment",
			input: "{\n  \"a\": 1, // This is a comment\n  \"b\": 2\n}",
			want:  "{\n  \"a\": 1,                     \n  \"b\": 2\n}",
		},
		{
			name:  "multi-line comment",
			input: "{\n  \"a\": 1, /* This is\n     a multi-line\n     comment */ \"b\": 2\n}",
			want:  "{\n  \"a\": 1,           \n                 \n                \"b\": 2\n}",
		},
		{
			name:  "comment with forward slash in string",
			input: "{\n  \"url\": \"http://example.com\", // Comment\n  \"value\": 123\n}",
			want:  "{\n  \"url\": \"http://example.com\",           \n  \"value\": 123\n}",
		},
		{
			name:  "trailing comma in object",
			input: `{"a": 1, "b": 2,}`,
			want:  `{"a": 1, "b": 2 }`,
		},
		{
			name:  "trailing comma in array",
			input: `[1, 2, 3,]`,
			want:  `[1, 2, 3 ]`,
		},
		{
			name:  "nested trailing commas",
			input: `{"a": [1, 2,], "b": {"x": 1, "y": 2,},}`,
			want:  `{"a": [1, 2 ], "b": {"x": 1, "y": 2 } }`,
		},
		{
			name:  "single-line comment at end of file without newline",
			input: `{"a": 1} // Comment`,
			want:  `{"a": 1}           `,
		},
		{
			name:  "multi-line comment at end of file",
			input: `{"a": 1} /* Comment */`,
			want:  `{"a": 1}              `,
		},
		{
			name:  "comment within string",
			input: `{"text": "This string has // comment syntax"}`,
			want:  `{"text": "This string has // comment syntax"}`,
		},
		{
			name:  "quoted comment markers",
			input: `{"a": "//", "b": "/*", "c": "*/"}`,
			want:  `{"a": "//", "b": "/*", "c": "*/"}`,
		},
		{
			name:  "escaped quotes in string",
			input: `{"text": "String with \"escaped quotes\" // not a comment"}`,
			want:  `{"text": "String with \"escaped quotes\" // not a comment"}`,
		},
		{
			name:  "complex escaped quotes",
			input: `{"text": "String with \\\"double escaped\\\" quotes"}`,
			want:  `{"text": "String with \\\"double escaped\\\" quotes"}`,
		},
		{
			name: "real world example",
			input: `{
  "name": "my-package", // Package name
  "version": "1.0.0",   /* Version number */
  "dependencies": {
    "lodash": "^4.17.21",
    "express": "^4.17.1", // Latest express
  },
  "scripts": {
    "start": "node index.js",
    "test": "jest",
  }
}`,
			want: `{
  "name": "my-package",                
  "version": "1.0.0",                       
  "dependencies": {
    "lodash": "^4.17.21",
    "express": "^4.17.1"                   
  },
  "scripts": {
    "start": "node index.js",
    "test": "jest" 
  }
}`,
		},
		{
			name: "preserves newlines in multiline comments",
			input: `{
  "name": "test", // Comment
  /* 
   * Multi-line
   * comment
   */
  "value": 42
}`,
			want: `{
  "name": "test",           
     
               
            
     
  "value": 42
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test ToRFC8259 (allocates new buffer)
			got := xjson.ToRFC8259([]byte(tt.input))

			// Check length preservation
			require.Len(t, got, len(tt.input), "output length should match input length")

			// Check content
			assert.Equal(t, tt.want, string(got))

			// Verify newline count is preserved
			inputNewlines := bytes.Count([]byte(tt.input), []byte{'\n'})
			outputNewlines := bytes.Count(got, []byte{'\n'})
			assert.Equal(t, inputNewlines, outputNewlines, "number of newlines should be preserved")

			// Make sure the output is valid JSON
			var jsonMap any
			err := xjson.Unmarshal(got, &jsonMap)
			require.NoError(t, err, "result should be valid JSON")
		})
	}
}

func TestUnmarshalJSONC(t *testing.T) {
	jsonc := `{
  "name": "test", // This is a comment
  "dependencies": {
    "lodash": "^4.17.21", /* Another comment */
    "express": "^4.17.1", // Comment
  }, // Trailing comment
  /* Multi-line
     comment */
  "version": "1.0.0"
}`

	type Config struct {
		Name         string            `json:"name"`
		Dependencies map[string]string `json:"dependencies"`
		Version      string            `json:"version"`
		xjson.Location
	}

	var config Config
	err := xjson.UnmarshalJSONC([]byte(jsonc), &config)
	require.NoError(t, err)

	// Verify the parsed content
	assert.Equal(t, "test", config.Name)
	assert.Equal(t, "1.0.0", config.Version)
	assert.Equal(t, map[string]string{
		"lodash":  "^4.17.21",
		"express": "^4.17.1",
	}, config.Dependencies)

	// Verify location information
	assert.Equal(t, 1, config.StartLine)
	assert.Equal(t, 10, config.EndLine)
}
