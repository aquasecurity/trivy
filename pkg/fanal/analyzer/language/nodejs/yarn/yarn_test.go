package yarn

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_yarnLibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		want *analyzer.AnalysisResult
	}{
		{
			name: "happy path",
			dir:  "testdata/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Yarn,
						FilePath: "yarn.lock",
						Libraries: types.Packages{
							{
								ID:      "js-tokens@2.0.0",
								Name:    "js-tokens",
								Version: "2.0.0",
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   8,
									},
								},
							},
							{
								ID:       "js-tokens@4.0.0",
								Name:     "js-tokens",
								Version:  "4.0.0",
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 10,
										EndLine:   13,
									},
								},
							},
							{
								ID:       "loose-envify@1.4.0",
								Name:     "loose-envify",
								Version:  "1.4.0",
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 15,
										EndLine:   20,
									},
								},
								DependsOn: []string{
									"js-tokens@4.0.0",
								},
							},
							{
								ID:       "object-assign@4.1.1",
								Name:     "object-assign",
								Version:  "4.1.1",
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 22,
										EndLine:   25,
									},
								},
							},
							{
								ID:      "prop-types@15.7.2",
								Name:    "prop-types",
								Version: "15.7.2",
								Dev:     true,
								Locations: []types.Location{
									{
										StartLine: 27,
										EndLine:   34,
									},
								},
								DependsOn: []string{
									"loose-envify@1.4.0",
									"object-assign@4.1.1",
									"react-is@16.13.1",
								},
							},
							{
								ID:       "react-is@16.13.1",
								Name:     "react-is",
								Version:  "16.13.1",
								Dev:      true,
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 36,
										EndLine:   39,
									},
								},
							},
							{
								ID:      "scheduler@0.13.6",
								Name:    "scheduler",
								Version: "0.13.6",
								Locations: []types.Location{
									{
										StartLine: 41,
										EndLine:   47,
									},
								},
								DependsOn: []string{
									"loose-envify@1.4.0",
									"object-assign@4.1.1",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "no package.json",
			dir:  "testdata/no-packagejson",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Yarn,
						FilePath: "yarn.lock",
						Libraries: types.Packages{
							{
								ID:      "js-tokens@2.0.0",
								Name:    "js-tokens",
								Version: "2.0.0",
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   8,
									},
								},
							},
							{
								ID:      "js-tokens@4.0.0",
								Name:    "js-tokens",
								Version: "4.0.0",
								Locations: []types.Location{
									{
										StartLine: 10,
										EndLine:   13,
									},
								},
							},
							{
								ID:      "loose-envify@1.4.0",
								Name:    "loose-envify",
								Version: "1.4.0",
								Locations: []types.Location{
									{
										StartLine: 15,
										EndLine:   20,
									},
								},
								DependsOn: []string{
									"js-tokens@4.0.0",
								},
							},
							{
								ID:      "object-assign@4.1.1",
								Name:    "object-assign",
								Version: "4.1.1",
								Locations: []types.Location{
									{
										StartLine: 22,
										EndLine:   25,
									},
								},
							},
							{
								ID:      "prop-types@15.7.2",
								Name:    "prop-types",
								Version: "15.7.2",
								Locations: []types.Location{
									{
										StartLine: 27,
										EndLine:   34,
									},
								},
								DependsOn: []string{
									"loose-envify@1.4.0",
									"object-assign@4.1.1",
									"react-is@16.13.1",
								},
							},
							{
								ID:      "react-is@16.13.1",
								Name:    "react-is",
								Version: "16.13.1",
								Locations: []types.Location{
									{
										StartLine: 36,
										EndLine:   39,
									},
								},
							},
							{
								ID:      "scheduler@0.13.6",
								Name:    "scheduler",
								Version: "0.13.6",
								Locations: []types.Location{
									{
										StartLine: 41,
										EndLine:   47,
									},
								},
								DependsOn: []string{
									"loose-envify@1.4.0",
									"object-assign@4.1.1",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "wrong package.json",
			dir:  "testdata/wrong-packagejson",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Yarn,
						FilePath: "yarn.lock",
						Libraries: types.Packages{
							{
								ID:      "js-tokens@2.0.0",
								Name:    "js-tokens",
								Version: "2.0.0",
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   8,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "unsupported_protocol",
			dir:  "testdata/unsupported_protocol",
			want: &analyzer.AnalysisResult{},
		},
		// docker run --rm -it node@sha256:2d5e8a8a51bc341fd5f2eed6d91455c3a3d147e91a14298fc564b5dc519c1666 sh
		// mkdir test && cd "$_"
		// yarn set version 3.4.1
		// yarn add is-callable@1.2.7 is-odd@3.0.1
		// yarn unplug is-callable@1.2.7
		// rm .yarn/cache/is-callable-npm*
		{
			name: "parse licenses (yarn v2+)",
			dir:  "testdata/yarn-licenses",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Yarn,
						FilePath: "yarn.lock",
						Libraries: []types.Package{
							{
								ID:       "is-callable@1.2.7",
								Name:     "is-callable",
								Version:  "1.2.7",
								Licenses: []string{"MIT"},
								Locations: []types.Location{
									{
										StartLine: 8,
										EndLine:   13,
									},
								},
							},
							{
								ID:       "is-number@6.0.0",
								Name:     "is-number",
								Version:  "6.0.0",
								Licenses: []string{"MIT"},
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 15,
										EndLine:   20,
									},
								},
							},
							{
								ID:        "is-odd@3.0.1",
								Name:      "is-odd",
								Version:   "3.0.1",
								Licenses:  []string{"MIT"},
								DependsOn: []string{"is-number@6.0.0"},
								Locations: []types.Location{
									{
										StartLine: 22,
										EndLine:   29,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "monorepo",
			dir:  "testdata/monorepo",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Yarn,
						FilePath: "yarn.lock",
						Libraries: types.Packages{
							{
								ID:       "is-number@6.0.0",
								Name:     "is-number",
								Version:  "6.0.0",
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 16,
										EndLine:   21,
									},
								},
							},
							{
								ID:      "is-number@7.0.0",
								Name:    "is-number",
								Version: "7.0.0",
								Locations: []types.Location{
									{
										StartLine: 23,
										EndLine:   28,
									},
								},
							},
							{
								ID:        "is-odd@3.0.1",
								Name:      "is-odd",
								Version:   "3.0.1",
								DependsOn: []string{"is-number@6.0.0"},
								Locations: []types.Location{
									{
										StartLine: 30,
										EndLine:   37,
									},
								},
							},
							{
								ID:       "js-tokens@4.0.0",
								Name:     "js-tokens",
								Version:  "4.0.0",
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 39,
										EndLine:   44,
									},
								},
							},
							{
								ID:      "js-tokens@8.0.1",
								Name:    "js-tokens",
								Version: "8.0.1",
								Locations: []types.Location{
									{
										StartLine: 46,
										EndLine:   51,
									},
								},
							},
							{
								ID:        "loose-envify@1.4.0",
								Name:      "loose-envify",
								Version:   "1.4.0",
								Indirect:  true,
								DependsOn: []string{"js-tokens@4.0.0"},
								Locations: []types.Location{
									{
										StartLine: 53,
										EndLine:   62,
									},
								},
							},
							{
								ID:       "object-assign@4.1.1",
								Name:     "object-assign",
								Version:  "4.1.1",
								Indirect: true,
								Dev:      true,
								Locations: []types.Location{
									{
										StartLine: 64,
										EndLine:   69,
									},
								},
							},
							{
								ID:      "prettier@2.8.8",
								Name:    "prettier",
								Version: "2.8.8",
								Dev:     true,
								Locations: []types.Location{
									{
										StartLine: 87,
										EndLine:   94,
									},
								},
							},
							{
								ID:      "prop-types@15.8.1",
								Name:    "prop-types",
								Version: "15.8.1",
								Dev:     true,
								Locations: []types.Location{
									{
										StartLine: 96,
										EndLine:   105,
									},
								},
								DependsOn: []string{
									"loose-envify@1.4.0",
									"object-assign@4.1.1",
									"react-is@16.13.1",
								},
							},
							{
								ID:       "react-is@16.13.1",
								Name:     "react-is",
								Version:  "16.13.1",
								Dev:      true,
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 107,
										EndLine:   112,
									},
								},
							},
							{
								ID:        "scheduler@0.23.0",
								Name:      "scheduler",
								Version:   "0.23.0",
								DependsOn: []string{"loose-envify@1.4.0"},
								Locations: []types.Location{
									{
										StartLine: 114,
										EndLine:   121,
									},
								},
							},
						},
					},
				},
			},
		},
		// docker run --rm -it node@sha256:2d5e8a8a51bc341fd5f2eed6d91455c3a3d147e91a14298fc564b5dc519c1666 sh
		// mkdir test && cd "$_"
		// yarn set version 1.22.19
		// yarn add @vue/compiler-sfc@2.7.14
		{
			name: "parse licenses (yarn classic)",
			dir:  "testdata/yarn-classic-licenses",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Yarn,
						FilePath: "yarn.lock",
						Libraries: []types.Package{
							{
								ID:       "@babel/parser@7.22.7",
								Name:     "@babel/parser",
								Version:  "7.22.7",
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   8,
									},
								},
								Licenses: []string{"MIT"},
							},
							{
								ID:       "@vue/compiler-sfc@2.7.14",
								Name:     "@vue/compiler-sfc",
								Version:  "2.7.14",
								Indirect: false,
								Locations: []types.Location{
									{
										StartLine: 10,
										EndLine:   17,
									},
								},
								Licenses: []string{"MIT"},
								DependsOn: []string{
									"@babel/parser@7.22.7",
									"postcss@8.4.27",
									"source-map@0.6.1",
								},
							},
							{
								ID:       "nanoid@3.3.6",
								Name:     "nanoid",
								Version:  "3.3.6",
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 19,
										EndLine:   22,
									},
								},
								Licenses: []string{"MIT"},
							},
							{
								ID:       "picocolors@1.0.0",
								Name:     "picocolors",
								Version:  "1.0.0",
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 24,
										EndLine:   27,
									},
								},
								Licenses: []string{"ISC"},
							},
							{
								ID:       "postcss@8.4.27",
								Name:     "postcss",
								Version:  "8.4.27",
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 29,
										EndLine:   36,
									},
								},
								Licenses: []string{"MIT"},
								DependsOn: []string{
									"nanoid@3.3.6",
									"picocolors@1.0.0",
									"source-map-js@1.0.2",
								},
							},
							{
								ID:       "source-map@0.6.1",
								Name:     "source-map",
								Version:  "0.6.1",
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 43,
										EndLine:   46,
									},
								},
								Licenses: []string{"BSD-3-Clause"},
							},
							{
								ID:       "source-map-js@1.0.2",
								Name:     "source-map-js",
								Version:  "1.0.2",
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 38,
										EndLine:   41,
									},
								},
								Licenses: []string{"BSD-3-Clause"},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newYarnAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(context.Background(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_yarnLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path yarn.lock",
			filePath: "test/yarn.lock",
			want:     true,
		},
		{
			name:     "sad path",
			filePath: "test/package-lock.json",
			want:     false,
		},
		{
			name:     "yarn cache",
			filePath: ".yarn/cache/websocket-driver-npm-0.7.4-a72739da70-fffe5a33fe.zip",
			want:     true,
		},
		{
			name:     "not a yarn cache",
			filePath: "cache/is-number-npm-6.0.0-30881e83e6-f73bfced03.zip",
			want:     false,
		},
		{
			name:     "yarn.lock in node_modules",
			filePath: "somedir/node_modules/uri-js/yarn.lock",
			want:     false,
		},
		{
			name:     "yarn.lock in unplugged",
			filePath: "somedir/.yarn/unplugged/uri-js/yarn.lock",
			want:     false,
		},
		{
			name:     "deep package.json",
			filePath: "somedir/node_modules/canvg/node_modules/parse5/package.json",
			want:     true,
		},
		{
			name:     "license file",
			filePath: "node_modules/@vue/compiler-sfc/LICENSE",
			want:     true,
		},
		{
			name:     "txt license file",
			filePath: "node_modules/@vue/compiler-sfc/LICENSE.txt",
			want:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := yarnAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
