package node

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestNodeAnalyzer_Analyze(t *testing.T) {
	f, err := os.Open("testdata/node_version.h")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })

	got, err := nodeAnalyzer{}.Analyze(t.Context(), analyzer.AnalysisInput{
		FilePath: "usr/local/include/node/node_version.h",
		Content:  f,
	})
	require.NoError(t, err)
	assert.Equal(t, &analyzer.AnalysisResult{Applications: []types.Application{{
		Type:     types.Node,
		FilePath: "usr/local/include/node/node_version.h",
		Packages: types.Packages{{
			ID:       "node@26.5.0",
			Name:     "node",
			Version:  "26.5.0",
			FilePath: "usr/local/include/node/node_version.h",
		}},
	}}}, got)
}

func TestNodeAnalyzer_Required(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: "usr/local/include/node/node_version.h", want: true},
		{path: "src/node_version.h", want: false},
		{path: "usr/local/include/node/node.h", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, nodeAnalyzer{}.Required(tt.path, nil))
		})
	}
}

func TestNodeAnalyzer_Metadata(t *testing.T) {
	a := nodeAnalyzer{}
	assert.Equal(t, analyzer.TypeNode, a.Type())
	assert.Equal(t, 2, a.Version())
}

func TestHeaderParser_Parse(t *testing.T) {
	for _, tt := range []struct {
		name, header, want string
		wantErr            bool
	}{
		{name: "complete", header: "#define NODE_MAJOR_VERSION 26\n#define NODE_MINOR_VERSION 12\n#define NODE_PATCH_VERSION 1\n", want: "26.12.1"},
		{name: "zero components", header: "#define NODE_MAJOR_VERSION 26\n#define NODE_MINOR_VERSION 0\n#define NODE_PATCH_VERSION 0\n", want: "26.0.0"},
		{name: "incomplete", header: "#define NODE_MAJOR_VERSION 26\n#define NODE_MINOR_VERSION 12\n"},
		{name: "invalid component", header: "#define NODE_MAJOR_VERSION invalid\n", wantErr: true},
		{name: "unrelated defines", header: "#define OTHER_VERSION 26\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pkgs, deps, err := (parser{}).Parse(t.Context(), strings.NewReader(tt.header))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Empty(t, deps)
			if tt.want == "" {
				assert.Empty(t, pkgs)
				return
			}
			assert.Equal(t, []types.Package{{ID: "node@" + tt.want, Name: "node", Version: tt.want}}, pkgs)
		})
	}
}
