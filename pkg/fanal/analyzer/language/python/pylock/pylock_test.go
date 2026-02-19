package pylock

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_pylockAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		want    *analyzer.AnalysisResult
		wantErr bool
	}{
		{
			name: "happy path",
			dir:  "testdata/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PyLock,
						FilePath: "pylock.toml",
						Packages: types.Packages{
							{
								ID:           "certifi@2025.1.31",
								Name:         "certifi",
								Version:      "2025.1.31",
								Relationship: types.RelationshipIndirect,
							},
							{
								ID:           "charset-normalizer@3.4.1",
								Name:         "charset-normalizer",
								Version:      "3.4.1",
								Relationship: types.RelationshipIndirect,
							},
							{
								ID:           "idna@3.10",
								Name:         "idna",
								Version:      "3.10",
								Relationship: types.RelationshipIndirect,
							},
							{
								ID:      "requests@2.32.3",
								Name:    "requests",
								Version: "2.32.3",
								DependsOn: []string{
									"certifi@2025.1.31",
									"charset-normalizer@3.4.1",
									"idna@3.10",
									"urllib3@2.3.0",
								},
								Relationship: types.RelationshipDirect,
							},
							{
								ID:           "urllib3@2.3.0",
								Name:         "urllib3",
								Version:      "2.3.0",
								Relationship: types.RelationshipIndirect,
							},
						},
					},
				},
			},
		},
		{
			name: "named lock file",
			dir:  "testdata/named",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PyLock,
						FilePath: "pylock.linux.toml",
						Packages: types.Packages{
							{
								ID:      "certifi@2025.1.31",
								Name:    "certifi",
								Version: "2025.1.31",
							},
						},
					},
				},
			},
		},
		{
			name: "with dev dependencies",
			dir:  "testdata/with-dev",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PyLock,
						FilePath: "pylock.toml",
						Packages: types.Packages{
							{
								ID:           "pytest@8.0.0",
								Name:         "pytest",
								Version:      "8.0.0",
								Relationship: types.RelationshipIndirect,
								Dev:          true,
							},
							{
								ID:      "requests@2.32.3",
								Name:    "requests",
								Version: "2.32.3",
								DependsOn: []string{
									"urllib3@2.3.0",
								},
								Relationship: types.RelationshipDirect,
							},
							{
								ID:           "urllib3@2.3.0",
								Name:         "urllib3",
								Version:      "2.3.0",
								Relationship: types.RelationshipIndirect,
							},
						},
					},
				},
			},
		},
		{
			name: "broken file",
			dir:  "testdata/broken",
			want: &analyzer.AnalysisResult{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newPylockAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_pylockAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path",
			filePath: "pylock.toml",
			want:     true,
		},
		{
			name:     "nested path",
			filePath: "some/dir/pylock.toml",
			want:     true,
		},
		{
			name:     "named lock file",
			filePath: "pylock.linux.toml",
			want:     true,
		},
		{
			name:     "named lock file with nested path",
			filePath: "some/dir/pylock.prod.toml",
			want:     true,
		},
		{
			name:     "named lock file with dots in identifier",
			filePath: "pylock.linux.arm64.toml",
			want:     true,
		},
		{
			name:     "wrong file",
			filePath: "requirements.txt",
			want:     false,
		},
		{
			name:     "similar but not pylock",
			filePath: "notpylock.toml",
			want:     false,
		},
		{
			name:     "pyproject.toml",
			filePath: "pyproject.toml",
			want:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := pylockAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
