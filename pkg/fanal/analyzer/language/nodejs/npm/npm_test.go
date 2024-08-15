package npm

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

func TestMain(m *testing.M) {
	log.InitLogger(false, true)
	os.Exit(m.Run())
}

func Test_npmLibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		want *analyzer.AnalysisResult
	}{
		{
			name: "with node_modules",
			dir:  "testdata/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Npm,
						FilePath: "package-lock.json",
						Packages: types.Packages{
							{
								ID:       "@babel/parser@7.23.6",
								Name:     "@babel/parser",
								Version:  "7.23.6",
								Licenses: []string{"MIT"},
								Locations: []types.Location{
									{
										StartLine: 6,
										EndLine:   10,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/@babel/parser/-/parser-7.23.6.tgz",
									},
								},
							},
							{
								ID:      "ansi-colors@3.2.3",
								Name:    "ansi-colors",
								Version: "3.2.3",
								Dev:     true,
								Locations: []types.Location{
									{
										StartLine: 11,
										EndLine:   16,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/ansi-colors/-/ansi-colors-3.2.3.tgz",
									},
								},
							},
							{
								ID:      "array-flatten@1.1.1",
								Name:    "array-flatten",
								Version: "1.1.1",
								Locations: []types.Location{
									{
										StartLine: 17,
										EndLine:   21,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/array-flatten/-/array-flatten-1.1.1.tgz",
									},
								},
							},
							{
								ID:        "body-parser@1.18.3",
								Name:      "body-parser",
								Version:   "1.18.3",
								DependsOn: []string{"debug@2.6.9"},
								Licenses:  []string{"MIT"},
								Locations: []types.Location{
									{
										StartLine: 22,
										EndLine:   44,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/body-parser/-/body-parser-1.18.3.tgz",
									},
								},
							},
							{
								ID:        "debug@2.6.9",
								Name:      "debug",
								Version:   "2.6.9",
								DependsOn: []string{"ms@2.0.0"},
								Licenses:  []string{"MIT"},
								Locations: []types.Location{
									{
										StartLine: 30,
										EndLine:   37,
									},
									{
										StartLine: 53,
										EndLine:   60,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz",
									},
								},
							},
							{
								ID:        "express@4.16.4",
								Name:      "express",
								Version:   "4.16.4",
								DependsOn: []string{"debug@2.6.9"},
								Licenses:  []string{"MIT"},
								Locations: []types.Location{
									{
										StartLine: 45,
										EndLine:   67,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/express/-/express-4.16.4.tgz",
									},
								},
							},
							{
								ID:       "ms@2.0.0",
								Name:     "ms",
								Version:  "2.0.0",
								Licenses: []string{"MIT"},
								Locations: []types.Location{
									{
										StartLine: 38,
										EndLine:   42,
									},
									{
										StartLine: 61,
										EndLine:   65,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz",
									},
								},
							},
							{
								ID:       "ms@2.1.1",
								Name:     "ms",
								Version:  "2.1.1",
								Licenses: []string{"MIT"},
								Locations: []types.Location{
									{
										StartLine: 68,
										EndLine:   72,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/ms/-/ms-2.1.1.tgz",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "without node_modules",
			dir:  "testdata/no-node_modules",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Npm,
						FilePath: "package-lock.json",
						Packages: types.Packages{
							{
								ID:      "ms@2.1.1",
								Name:    "ms",
								Version: "2.1.1",
								Locations: []types.Location{
									{
										StartLine: 6,
										EndLine:   10,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/ms/-/ms-2.1.1.tgz",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "sad path",
			dir:  "testdata/sad",
			want: &analyzer.AnalysisResult{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newNpmLibraryAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(context.Background(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			require.NoError(t, err)
			if len(got.Applications) > 0 {
				sort.Sort(got.Applications[0].Packages)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_nodePkgLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "lock file",
			filePath: "npm/package-lock.json",
			want:     true,
		},
		{
			name:     "package.json",
			filePath: "npm/node_modules/ms/package.json",
			want:     true,
		},
		{
			name:     "package.json with `/` in name",
			filePath: "npm/node_modules/@babel/parser/package.json",
			want:     true,
		},
		{
			name:     "sad path",
			filePath: "npm/package.json",
			want:     false,
		},
		{
			name:     "lock file in node_modules",
			filePath: "npm/node_modules/html2canvas/package-lock.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := npmLibraryAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDeepLicenseScanning(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		want *analyzer.AnalysisResult
	}{
		{
			name: "deep-license-scan",
			dir:  "testdata/deep-license-scan",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Npm,
						FilePath: "package-lock.json",
						Packages: types.Packages{
							{
								ID:      "babel-runtime@6.26.0",
								Name:    "babel-runtime",
								Version: "6.26.0",
								Licenses: []string{
									"MIT",
								},
								ConcludedLicenses: []types.License{
									{
										Name:                "Apache-2.0",
										Type:                "header",
										IsDeclared:          false,
										FilePath:            "node_modules/babel-runtime/node_modules/core-js/test2.go",
										LicenseTextChecksum: "bdc80008ee57ce3815ac3d8be33e4bad3508d5729dd8cbbbe6c799245ee77edd",
										CopyrightText:       "",
									},
									{
										Name:                "BSD-3-Clause",
										Type:                "license-file",
										IsDeclared:          false,
										FilePath:            "node_modules/babel-runtime/LICENSE",
										LicenseTextChecksum: "385bce4f8bf50fb890c351674d4eac08fae03de787f2b37332f6184245706df6",
										CopyrightText:       "",
									},
								},

								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								DependsOn: []string{
									"core-js@2.6.12",
									"regenerator-runtime@0.11.1",
								},
								Locations: []types.Location{
									{
										StartLine: 11,
										EndLine:   19,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/babel-runtime/-/babel-runtime-6.26.0.tgz",
									},
								},
							},
							{
								ID:           "core-js@2.6.12",
								Name:         "core-js",
								Version:      "2.6.12",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 20,
										EndLine:   26,
									},
									{
										StartLine: 59,
										EndLine:   63,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/core-js/-/core-js-2.6.12.tgz",
									},
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/regenerator-runtime/-/regenerator-runtime-0.11.1.tgz",
									},
								},
							},
							{
								ID:      "jiti@1.21.0",
								Name:    "jiti",
								Version: "1.21.0",
								Licenses: []string{
									"MIT",
								},
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								DependsOn: []string{
									"ninja@6.26.0",
								},
								Locations: []types.Location{
									{
										StartLine: 32,
										EndLine:   39,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/babel-runtime/-/babel-runtime-6.26.0.tgz",
									},
								},
							},
							{
								ID:           "jujutsu@1.20.20",
								Name:         "jujutsu",
								Version:      "1.20.20",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								DependsOn: []string{
									"regenerator-runtime@0.11.1",
								},
								Locations: []types.Location{
									{
										StartLine: 45,
										EndLine:   53,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/babel-runtime/-/babel-runtime-6.26.0.tgz",
									},
								},
							},
							{
								ID:      "ninja@6.26.0",
								Name:    "ninja",
								Version: "6.26.0",
								Licenses: []string{
									"MIT",
								},
								ConcludedLicenses: []types.License{
									{
										Name:                "GPL-2.0",
										Type:                "header",
										IsDeclared:          false,
										FilePath:            "node_modules/jiti/node_modules/ninja/LICENSE",
										LicenseTextChecksum: "1d1291699fa1a23d6414a3a3994dcf8db6bacf6c5ab6624a7231b1543e6dfe27",
										CopyrightText:       "",
									},
								},
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 40,
										EndLine:   44,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/babel-runtime/-/babel-runtime-6.26.0.tgz",
									},
								},
							},
							{
								ID:      "regenerator-runtime@0.11.1",
								Name:    "regenerator-runtime",
								Version: "0.11.1",
								Licenses: []string{
									"MIT",
									"MIT",
								},
								ConcludedLicenses: []types.License{
									{
										Name:                "BSD-3-Clause",
										Type:                "license-file",
										IsDeclared:          false,
										FilePath:            "node_modules/babel-runtime/node_modules/regenerator-runtime/LICENSE",
										LicenseTextChecksum: "385bce4f8bf50fb890c351674d4eac08fae03de787f2b37332f6184245706df6",
										CopyrightText:       "",
									},
									{
										Name:                "Apache-2.0",
										Type:                "header",
										IsDeclared:          false,
										FilePath:            "node_modules/babel-runtime/node_modules/regenerator-runtime/test1.go",
										LicenseTextChecksum: "3ecd2b1a881c13670817e5db77bcfeaa3b76e318ca96037301d6488ff5cd71d6",
										CopyrightText:       "",
									},
									{
										Name:                "BSD-3-Clause",
										Type:                "license-file",
										IsDeclared:          false,
										FilePath:            "node_modules/babel-runtime/node_modules/regenerator-runtime/.git/LICENSE",
										LicenseTextChecksum: "0497daad1a4b665867ffbc3c7e23a4d3bc9f40b8f0f18647c991353176606784",
										CopyrightText:       "",
									},
								},
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 27,
										EndLine:   31,
									},
									{
										StartLine: 54,
										EndLine:   58,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/regenerator-runtime/-/regenerator-runtime-0.11.1.tgz",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newNpmLibraryAnalyzer(analyzer.AnalyzerOptions{
				LicenseScannerOption: analyzer.LicenseScannerOption{
					Enabled:                   true,
					Full:                      true,
					LicenseScanWorkers:        5,
					ClassifierConfidenceLevel: 0.75,
				},
			})
			require.NoError(t, err)

			got, err := a.PostAnalyze(context.Background(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})
			require.NoError(t, err)

			if len(got.Applications) > 0 {
				sort.Sort(got.Applications[0].Packages)
			}

			// sort the licenses
			for _, app := range got.Applications {
				packages := app.Packages
				for _, pkg := range packages {
					slices.Sort(pkg.Licenses)
					sort.SliceStable(pkg.ConcludedLicenses, func(i, j int) bool {
						return pkg.ConcludedLicenses[i].Name <= pkg.ConcludedLicenses[j].Name &&
							pkg.ConcludedLicenses[i].FilePath < pkg.ConcludedLicenses[j].FilePath
					})
				}
			}

			for _, app := range tt.want.Applications {
				packages := app.Packages
				for _, pkg := range packages {
					slices.Sort(pkg.Licenses)
					sort.SliceStable(pkg.ConcludedLicenses, func(i, j int) bool {
						return pkg.ConcludedLicenses[i].Name <= pkg.ConcludedLicenses[j].Name &&
							pkg.ConcludedLicenses[i].FilePath < pkg.ConcludedLicenses[j].FilePath
					})
				}
			}

			// compared the serialized jsons
			serializedGot, err := json.Marshal(got.Applications)
			require.NoError(t, err)

			serializedWant, err := json.Marshal(tt.want.Applications)
			require.NoError(t, err)

			assert.Equal(t, string(serializedWant), string(serializedGot))
		})
	}
}
