package node

import (
	"context"
	"os"
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

	got, err := nodeAnalyzer{}.Analyze(context.Background(), analyzer.AnalysisInput{
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
	assert.Equal(t, 1, a.Version())
}
