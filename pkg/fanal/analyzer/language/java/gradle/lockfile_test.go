package gradle

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_gradleLockAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name     string
		dir      string
		cacheDir string
		want     *analyzer.AnalysisResult
	}{
		{
			name:     "happy path",
			dir:      "testdata/lockfiles/happy",
			cacheDir: "testdata/cache",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Gradle,
						FilePath: "gradle.lockfile",
						Libraries: types.Packages{
							{
								ID:       "junit:junit:4.13",
								Name:     "junit:junit",
								Version:  "4.13",
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 4,
										EndLine:   4,
									},
								},
								Licenses: []string{
									"Eclipse Public License 1.0",
								},
								DependsOn: []string{
									"org.hamcrest:hamcrest-core:1.3",
								},
							},
							{
								ID:       "org.hamcrest:hamcrest-core:1.3",
								Name:     "org.hamcrest:hamcrest-core",
								Version:  "1.3",
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   5,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path without cache",
			dir:  "testdata/lockfiles/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Gradle,
						FilePath: "gradle.lockfile",
						Libraries: types.Packages{
							{
								ID:       "junit:junit:4.13",
								Name:     "junit:junit",
								Version:  "4.13",
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 4,
										EndLine:   4,
									},
								},
							},
							{
								ID:       "org.hamcrest:hamcrest-core:1.3",
								Name:     "org.hamcrest:hamcrest-core",
								Version:  "1.3",
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   5,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "empty file",
			dir:  "testdata/lockfiles/empty",
			want: &analyzer.AnalysisResult{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.cacheDir != "" {
				t.Setenv("GRADLE_USER_HOME", tt.cacheDir)
			}

			a, err := newGradleLockAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(context.Background(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_nugetLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "default name",
			filePath: "test/gradle.lockfile",
			want:     true,
		},
		{
			name:     "name with prefix",
			filePath: "test/settings-gradle.lockfile",
			want:     true,
		},
		{
			name:     "txt",
			filePath: "test/test.txt",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := gradleLockAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
