package conan

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_conanLockAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name     string
		dir      string
		cacheDir map[string]string
		want     *analyzer.AnalysisResult
	}{
		{
			name: "happy path V1",
			dir:  "testdata/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Conan,
						FilePath: "conan.lock",
						Packages: types.Packages{
							{
								ID:           "openssl/3.0.5",
								Name:         "openssl",
								Version:      "3.0.5",
								Relationship: types.RelationshipDirect,
								DependsOn: []string{
									"zlib/1.2.12",
								},
								Locations: []types.Location{
									{
										StartLine: 12,
										EndLine:   21,
									},
								},
							},
							{
								ID:           "zlib/1.2.12",
								Name:         "zlib",
								Version:      "1.2.12",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 22,
										EndLine:   28,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path V1 with cache dir",
			dir:  "testdata/happy",
			cacheDir: map[string]string{
				"CONAN_USER_HOME": "testdata/cacheDir",
			},
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Conan,
						FilePath: "conan.lock",
						Packages: types.Packages{
							{
								ID:      "openssl/3.0.5",
								Name:    "openssl",
								Version: "3.0.5",
								Licenses: []string{
									"Apache-2.0",
								},
								DependsOn: []string{
									"zlib/1.2.12",
								},
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 12,
										EndLine:   21,
									},
								},
							},
							{
								ID:      "zlib/1.2.12",
								Name:    "zlib",
								Version: "1.2.12",
								Licenses: []string{
									"Zlib",
								},
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 22,
										EndLine:   28,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path V2",
			dir:  "testdata/happy_v2",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Conan,
						FilePath: "release.lock",
						Packages: types.Packages{
							{
								ID:           "openssl/3.2.2",
								Name:         "openssl",
								Version:      "3.2.2",
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   5,
									},
								},
							},
							{
								ID:           "zlib/1.3.1",
								Name:         "zlib",
								Version:      "1.3.1",
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 4,
										EndLine:   4,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path V2 with cache dir",
			dir:  "testdata/happy_v2",
			cacheDir: map[string]string{
				"CONAN_HOME": "testdata/cacheDir_v2",
			},
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Conan,
						FilePath: "release.lock",
						Packages: types.Packages{

							{
								ID:           "openssl/3.2.2",
								Name:         "openssl",
								Version:      "3.2.2",
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   5,
									},
								},
								Licenses: []string{
									"Apache-2.0",
								},
							},
							{
								ID:           "zlib/1.3.1",
								Name:         "zlib",
								Version:      "1.3.1",
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 4,
										EndLine:   4,
									},
								},
								Licenses: []string{
									"Zlib",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "empty file",
			dir:  "testdata/empty",
			want: &analyzer.AnalysisResult{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.cacheDir) > 0 {
				for env, path := range tt.cacheDir {
					t.Setenv(env, path)
					break
				}
			}
			a, err := newConanLockAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(context.Background(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func Test_conanLockAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "default name",
			filePath: "conan.lock",
			want:     true,
		},
		{
			name:     "name with prefix",
			filePath: "pkga_deps.lock",
			want:     false,
		},
		{
			name:     "txt",
			filePath: "test.txt",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := conanLockAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_detectAttribute(t *testing.T) {
	tests := []struct {
		name     string
		attrName string
		line     string
		want     string
	}{
		{
			name:     "without spaces near `=`",
			attrName: "license",
			line:     `license="bar"`,
			want:     "bar",
		},
		{
			name:     "with space before `=`",
			attrName: "license",
			line:     `license ="bar"`,
			want:     "bar",
		},
		{
			name:     "with space after `=`",
			attrName: "license",
			line:     `license= "bar"`,
			want:     "bar",
		},
		{
			name:     "with space before and after `=`",
			attrName: "license",
			line:     `license = "bar"`,
			want:     "bar",
		},
		{
			name:     "license with spaces",
			attrName: "license",
			line:     `license = "foo and bar"`,
			want:     "foo and bar",
		},
		{
			name:     "another attribute",
			attrName: "license",
			line:     `license_contents = "foo"`,
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectAttribute(tt.attrName, tt.line)
			require.Equal(t, tt.want, got)
		})
	}
}
