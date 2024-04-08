package spdx_test

import (
	"encoding/json"
	sbomio "github.com/aquasecurity/trivy/pkg/sbom/io"
	"github.com/package-url/packageurl-go"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom/spdx"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestUnmarshaler_Unmarshal(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      types.SBOM
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy/bom.json",
			want: types.SBOM{
				Metadata: types.Metadata{
					ImageID: "sha256:49193a2310dbad4c02382da87ac624a80a92387a4f7536235f9ba590e5bcd7b5",
					DiffIDs: []string{
						"sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
						"sha256:dd565ff850e7003356e2b252758f9bdc1ff2803f61e995e24c7844f6297f8fc3",
					},
					RepoTags: []string{
						"maven-test-project:latest",
						"tmp-test:latest",
					},
					OS: &ftypes.OS{
						Family: "alpine",
						Name:   "3.16.0",
					},
				},
				Packages: []ftypes.PackageInfo{
					{
						Packages: ftypes.Packages{
							{
								ID:         "musl@1.2.3-r0",
								Name:       "musl",
								Version:    "1.2.3-r0",
								SrcName:    "musl",
								SrcVersion: "1.2.3-r0",
								Licenses:   []string{"MIT"},
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeApk,
										Namespace: "alpine",
										Name:      "musl",
										Version:   "1.2.3-r0",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "distro",
												Value: "3.16.0",
											},
										},
									},
								},
								Layer: ftypes.Layer{
									DiffID: "sha256:dd565ff850e7003356e2b252758f9bdc1ff2803f61e995e24c7844f6297f8fc3",
								},
							},
						},
					},
				},
				Applications: []ftypes.Application{
					{
						Type:     "composer",
						FilePath: "app/composer/composer.lock",
						Libraries: ftypes.Packages{
							{
								ID:      "pear/log@1.13.1",
								Name:    "pear/log",
								Version: "1.13.1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "log",
										Version:   "1.13.1",
									},
								},
								Layer: ftypes.Layer{
									DiffID: "sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
								},
							},
							{
								ID:      "pear/pear_exception@v1.0.0",
								Name:    "pear/pear_exception",
								Version: "v1.0.0",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "pear_exception",
										Version:   "v1.0.0",
									},
								},
								Layer: ftypes.Layer{
									DiffID: "sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
								},
							},
						},
					},
					{
						Type:     "gobinary",
						FilePath: "app/gobinary/gobinary",
						Libraries: ftypes.Packages{
							{
								ID:      "github.com/package-url/packageurl-go@v0.1.1-0.20220203205134-d70459300c8a",
								Name:    "github.com/package-url/packageurl-go",
								Version: "v0.1.1-0.20220203205134-d70459300c8a",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeGolang,
										Namespace: "github.com/package-url",
										Name:      "packageurl-go",
										Version:   "v0.1.1-0.20220203205134-d70459300c8a",
									},
								},
								Layer: ftypes.Layer{
									DiffID: "sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
								},
							},
						},
					},
					{
						Type: "jar",
						Libraries: ftypes.Packages{
							{
								ID:   "org.codehaus.mojo:child-project:1.0",
								Name: "org.codehaus.mojo:child-project",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "org.codehaus.mojo",
										Name:      "child-project",
										Version:   "1.0",
									},
								},
								Version: "1.0",
								Layer: ftypes.Layer{
									DiffID: "sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
								},
							},
						},
					},
					{
						Type: "node-pkg",
						Libraries: ftypes.Packages{
							{
								ID:      "bootstrap@5.0.2",
								Name:    "bootstrap",
								Version: "5.0.2",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeNPM,
										Name:    "bootstrap",
										Version: "5.0.2",
									},
								},
								Licenses: []string{"MIT"},
								Layer: ftypes.Layer{
									DiffID: "sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path for bom with hasFiles field",
			inputFile: "testdata/happy/with-hasfiles-bom.json",
			want: types.SBOM{
				Applications: []ftypes.Application{
					{
						Type: ftypes.NodePkg,
						Libraries: ftypes.Packages{
							{
								ID:       "yargs-parser@21.1.1",
								Name:     "yargs-parser",
								Version:  "21.1.1",
								Licenses: []string{"ISC"},
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeNPM,
										Name:    "yargs-parser",
										Version: "21.1.1",
									},
								},
								FilePath: "node_modules/yargs-parser/package.json",
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path for bom files in relationships",
			inputFile: "testdata/happy/with-files-in-relationships-bom.json",
			want: types.SBOM{
				Applications: []ftypes.Application{
					{
						Type: "node-pkg",
						Libraries: ftypes.Packages{
							{
								ID:       "yargs-parser@21.1.1",
								Name:     "yargs-parser",
								Version:  "21.1.1",
								Licenses: []string{"ISC"},
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeNPM,
										Name:    "yargs-parser",
										Version: "21.1.1",
									},
								},
								FilePath: "node_modules/yargs-parser/package.json",
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path for unrelated bom",
			inputFile: "testdata/happy/unrelated-bom.json",
			want: types.SBOM{
				Applications: []ftypes.Application{
					{
						Type:     "composer",
						FilePath: "app/composer/composer.lock",
						Libraries: ftypes.Packages{
							{
								ID:      "pear/log@1.13.1",
								Name:    "pear/log",
								Version: "1.13.1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "log",
										Version:   "1.13.1",
									},
								},
							},
							{
								ID:      "pear/pear_exception@v1.0.0",
								Name:    "pear/pear_exception",
								Version: "v1.0.0",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "pear_exception",
										Version:   "v1.0.0",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path with no relationship",
			inputFile: "testdata/happy/no-relationship.json",
			want: types.SBOM{
				Applications: []ftypes.Application{
					{
						Type: ftypes.Jar,
						Libraries: ftypes.Packages{
							{
								ID:       "co.elastic.apm:apm-agent:1.36.0",
								Name:     "co.elastic.apm:apm-agent",
								Version:  "1.36.0",
								FilePath: "modules/apm/elastic-apm-agent-1.36.0.jar",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "co.elastic.apm",
										Name:      "apm-agent",
										Version:   "1.36.0",
									},
								},
							},
							{
								ID:       "co.elastic.apm:apm-agent-cached-lookup-key:1.36.0",
								Name:     "co.elastic.apm:apm-agent-cached-lookup-key",
								Version:  "1.36.0",
								FilePath: "modules/apm/elastic-apm-agent-1.36.0.jar",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "co.elastic.apm",
										Name:      "apm-agent-cached-lookup-key",
										Version:   "1.36.0",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path with file as parent of relationship",
			inputFile: "testdata/happy/with-file-as-relationship-parent.json",
			want:      types.SBOM{},
		},
		{
			name:      "happy path only os component",
			inputFile: "testdata/happy/os-only-bom.json",
			want: types.SBOM{
				Metadata: types.Metadata{
					OS: &ftypes.OS{
						Family: "alpine",
						Name:   "3.16.0",
					},
				},
			},
		},
		{
			name:      "happy path empty component",
			inputFile: "testdata/happy/empty-bom.json",
			want:      types.SBOM{},
		},
		{
			name:      "sad path invalid purl",
			inputFile: "testdata/sad/invalid-purl.json",
			wantErr:   "purl is missing type or name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			var v spdx.SPDX
			err = json.NewDecoder(f).Decode(&v)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			var got types.SBOM
			err = sbomio.NewDecoder(v.BOM).Decode(&got)
			require.NoError(t, err)

			// Not compare BOM
			got.BOM = nil

			sort.Slice(got.Applications, func(i, j int) bool {
				return got.Applications[i].Type < got.Applications[j].Type
			})
			assert.Equal(t, tt.want, got)
		})
	}
}
