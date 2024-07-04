package spdx_test

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	sbomio "github.com/aquasecurity/trivy/pkg/sbom/io"
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
									BOMRef: "Package-b7ebaf0233f1ef7b",
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
						Packages: ftypes.Packages{
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
									BOMRef: "Package-2906575950df652b",
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
									BOMRef: "Package-5e2e255ac76747ef",
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
						Packages: ftypes.Packages{
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
									BOMRef: "Package-84ebffe38343d949",
								},
								Layer: ftypes.Layer{
									DiffID: "sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
								},
							},
						},
					},
					{
						Type: "jar",
						Packages: ftypes.Packages{
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
									BOMRef: "Package-2a53baa495b9ddaf",
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
						Packages: ftypes.Packages{
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
									BOMRef: "Package-5f1dbaff8de5eb06",
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
						Packages: ftypes.Packages{
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
									BOMRef: "Package-c3508825bf3861d8",
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
						Packages: ftypes.Packages{
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
									BOMRef: "Package-c3508825bf3861d8",
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
						Packages: ftypes.Packages{
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
									BOMRef: "Package-2906575950df652b",
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
									BOMRef: "Package-5e2e255ac76747ef",
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
						Packages: ftypes.Packages{
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
									BOMRef: "Package-d6465ccdd5385c16",
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
									BOMRef: "Package-8e3a2cf58d7bd790",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path multiple OS. OS is selected by number of packages",
			inputFile: "testdata/happy/select-os-by-number-of-pkgs.json",
			want: types.SBOM{
				Metadata: types.Metadata{
					OS: &ftypes.OS{
						Family: "debian",
						Name:   "12.5",
					},
				},
				Packages: []ftypes.PackageInfo{
					{
						Packages: ftypes.Packages{
							{
								ID:         "libmd0@1.0.4-2",
								Name:       "libmd0",
								Version:    "1.0.4-2",
								Arch:       "arm64",
								SrcName:    "libmd",
								SrcVersion: "1.0.4",
								SrcRelease: "2",
								Licenses:   []string{"MIT"},
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeDebian,
										Namespace: "debian",
										Name:      "libmd0",
										Version:   "1.0.4-2",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "arch",
												Value: "arm64",
											},
											{
												Key:   "distro",
												Value: "debian-12.5",
											},
										},
									},
									BOMRef: "Package-gnrtd175",
								},
							},
							{
								ID:         "libmount1@2.38.1-5+deb12u1",
								Name:       "libmount1",
								Version:    "2.38.1-5+deb12u1",
								Arch:       "arm64",
								SrcName:    "util-linux",
								SrcVersion: "2.38.1",
								SrcRelease: "5+deb12u1",
								Licenses:   []string{"MIT"},
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeDebian,
										Namespace: "debian",
										Name:      "libmount1",
										Version:   "2.38.1-5+deb12u1",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "arch",
												Value: "arm64",
											},
											{
												Key:   "distro",
												Value: "debian-12.5",
											},
										},
									},
									BOMRef: "Package-gnrtd259",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path multiple OS. OS is selected by SPDXID",
			inputFile: "testdata/happy/select-os-by-spdxid.json",
			want: types.SBOM{
				Metadata: types.Metadata{
					OS: &ftypes.OS{
						Family: "debian",
						Name:   "12.0",
					},
				},
				Packages: []ftypes.PackageInfo{
					{
						Packages: ftypes.Packages{
							{
								ID:         "libedit2@3.1-20221030-2",
								Name:       "libedit2",
								Version:    "3.1-20221030-2",
								Arch:       "amd64",
								SrcName:    "libedit",
								SrcVersion: "3.1-20221030",
								SrcRelease: "2",
								Licenses:   []string{"BSD-3-Clause"},
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeDebian,
										Namespace: "debian",
										Name:      "libedit2",
										Version:   "3.1-20221030-2",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "arch",
												Value: "amd64",
											},
											{
												Key:   "distro",
												Value: "debian-12.0",
											},
										},
									},
									BOMRef: "Package-gnrtd7",
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
			err = sbomio.NewDecoder(v.BOM).Decode(context.Background(), &got)
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
