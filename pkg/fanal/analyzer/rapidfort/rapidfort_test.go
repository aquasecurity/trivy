package rapidfort

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_curatedAnalyzer_Analyze(t *testing.T) {
	a := curatedAnalyzer{}
	got, err := a.Analyze(t.Context(), analyzer.AnalysisInput{
		FilePath: curatedFilePath,
		Content:  strings.NewReader(""),
	})
	require.NoError(t, err)
	want := &analyzer.AnalysisResult{
		CustomResources: []types.CustomResource{
			{
				Type:     CustomResourceType,
				FilePath: curatedFilePath,
			},
		},
	}
	assert.Equal(t, want, got)
}

func Test_curatedAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "curated sentinel file",
			filePath: "usr/share/rapidfort/curated.json",
			want:     true,
		},
		{
			name:     "unrelated path under same tree",
			filePath: "usr/share/rapidfort/other.json",
			want:     false,
		},
		{
			name:     "unrelated path",
			filePath: "etc/os-release",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := curatedAnalyzer{}
			assert.Equal(t, tt.want, a.Required(tt.filePath, nil))
		})
	}
}

func Test_curatedAnalyzer_StaticPaths(t *testing.T) {
	a := curatedAnalyzer{}
	assert.Equal(t, []string{"usr/share/rapidfort/curated.json"}, a.StaticPaths())
}

func Test_curatedAnalyzer_Type(t *testing.T) {
	a := curatedAnalyzer{}
	assert.Equal(t, analyzer.TypeRapidFortCurated, a.Type())
}
