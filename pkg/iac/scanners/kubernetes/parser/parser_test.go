package parser_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/kubernetes/parser"
)

func TestParse(t *testing.T) {
	const filePath = "test.yaml"

	type lines struct {
		start int
		end   int
	}

	tests := []struct {
		name          string
		src           string
		expectedLines []lines
	}{
		{
			name:          "empty file",
			src:           "",
			expectedLines: nil,
		},
		{
			name: "single YAML without separator",
			src: `
apiVersion: v1
kind: Pod
`,
			expectedLines: []lines{{start: 2, end: 3}},
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
			expectedLines: []lines{{start: 2, end: 3}, {start: 5, end: 6}},
		},
		{
			name: "YAML with multiple empty blocks",
			src: `---

---
---
apiVersion: v1
kind: Pod
`,
			expectedLines: []lines{{start: 5, end: 6}},
		},
		{
			name:          "Windows line endings",
			src:           "---\r\napiVersion: v1\r\nkind: Pod\r\n",
			expectedLines: []lines{{start: 2, end: 3}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifests, err := parser.Parse(t.Context(), strings.NewReader(tt.src), filePath)
			require.NoError(t, err)
			require.Len(t, manifests, len(tt.expectedLines))

			for i, manifest := range manifests {
				require.NotNil(t, manifest.Content)
				require.Equal(t, tt.expectedLines[i].start, manifest.Content.StartLine)
				require.Equal(t, tt.expectedLines[i].end, manifest.Content.EndLine)
			}
		})
	}
}
