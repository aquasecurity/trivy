package parser_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/kubernetes/parser"
)

func TestParse(t *testing.T) {
	const filePath = "test.yaml"

	tests := []struct {
		name            string
		src             string
		expectedOffsets []int
	}{
		{
			name:            "empty file",
			src:             "",
			expectedOffsets: nil,
		},
		{
			name: "single YAML without separator",
			src: `
apiVersion: v1
kind: Pod
`,
			expectedOffsets: []int{0},
		},
		{
			name: "multiple YAML documents",
			src: `---
apiVersion: v1
kind: Pod
---
apiVersion: v1
kind: Service
`,
			expectedOffsets: []int{1, 3},
		},
		{
			name: "YAML with multiple empty blocks",
			src: `---

---
---
apiVersion: v1
kind: Pod
`,
			expectedOffsets: []int{3},
		},
		{
			name:            "Windows line endings",
			src:             "---\r\napiVersion: v1\r\nkind: Pod\r\n",
			expectedOffsets: []int{1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifests, err := parser.Parse(t.Context(), strings.NewReader(tt.src), filePath)
			require.NoError(t, err)
			require.Len(t, manifests, len(tt.expectedOffsets))

			for i, manifest := range manifests {
				require.NotNil(t, manifest.Content)
				require.Equal(t, tt.expectedOffsets[i], manifest.Content.Offset)
			}
		})
	}
}

func TestParse_WhitespaceOnly(t *testing.T) {
	const filePath = "test.yaml"

	tests := []struct {
		name string
		src  string
	}{
		{name: "single space", src: " "},
		{name: "multiple spaces", src: "    "},
		{name: "single newline", src: "\n"},
		{name: "multiple newlines", src: "\n\n\n"},
		{name: "tabs only", src: "\t\t"},
		{name: "mixed whitespace", src: "  \t\n  \r\n\t "},
		{name: "CRLF only", src: "\r\n\r\n"},
		{name: "BOM only", src: "\xef\xbb\xbf"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				manifests, err := parser.Parse(t.Context(), strings.NewReader(tt.src), filePath)
				require.NoError(t, err)
				require.Empty(t, manifests)
			})
		})
	}
}
