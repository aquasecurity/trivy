package spdx_test

import (
	"encoding/json"
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
				OS: ftypes.OS{
					Family: "alpine",
					Name:   "3.16.0",
				},
				Packages: []ftypes.PackageInfo{
					{
						Packages: ftypes.Packages{
							{
								Name:       "musl",
								Version:    "1.2.3-r0",
								SrcName:    "musl",
								SrcVersion: "1.2.3-r0",
								Licenses:   []string{"MIT"},
								Ref:        "pkg:apk/alpine/musl@1.2.3-r0?distro=3.16.0",
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
								Name:    "pear/log",
								Version: "1.13.1",
								Ref:     "pkg:composer/pear/log@1.13.1",
								Layer: ftypes.Layer{
									DiffID: "sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
								},
							},
							{

								Name:    "pear/pear_exception",
								Version: "v1.0.0",
								Ref:     "pkg:composer/pear/pear_exception@v1.0.0",
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
								Name:    "github.com/package-url/packageurl-go",
								Version: "v0.1.1-0.20220203205134-d70459300c8a",
								Ref:     "pkg:golang/github.com/package-url/packageurl-go@v0.1.1-0.20220203205134-d70459300c8a",
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
								Name:    "org.codehaus.mojo:child-project",
								Ref:     "pkg:maven/org.codehaus.mojo/child-project@1.0",
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
								Name:     "bootstrap",
								Version:  "5.0.2",
								Ref:      "pkg:npm/bootstrap@5.0.2",
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
						Type: "node-pkg",
						Libraries: ftypes.Packages{
							{
								ID:       "yargs-parser@21.1.1",
								Name:     "yargs-parser",
								Version:  "21.1.1",
								Licenses: []string{"ISC"},
								Ref:      "pkg:npm/yargs-parser@21.1.1",
								FilePath: "node_modules/yargs-parser/package.json",
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
						Type: "node-pkg",
						Libraries: ftypes.Packages{
							{
								ID:       "yargs-parser@21.1.1",
								Name:     "yargs-parser",
								Version:  "21.1.1",
								Licenses: []string{"ISC"},
								Ref:      "pkg:npm/yargs-parser@21.1.1",
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
								Ref:      "pkg:npm/yargs-parser@21.1.1",
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
								Name:    "pear/log",
								Version: "1.13.1",
								Ref:     "pkg:composer/pear/log@1.13.1",
							},
							{

								Name:    "pear/pear_exception",
								Version: "v1.0.0",
								Ref:     "pkg:composer/pear/pear_exception@v1.0.0",
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
								FilePath: "modules/apm/elastic-apm-agent-1.36.0.jar",
								Name:     "co.elastic.apm:apm-agent",
								Version:  "1.36.0",
								Ref:      "pkg:maven/co.elastic.apm/apm-agent@1.36.0",
							},
							{
								FilePath: "modules/apm/elastic-apm-agent-1.36.0.jar",
								Name:     "co.elastic.apm:apm-agent-cached-lookup-key",
								Version:  "1.36.0",
								Ref:      "pkg:maven/co.elastic.apm/apm-agent-cached-lookup-key@1.36.0",
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path only os component",
			inputFile: "testdata/happy/os-only-bom.json",
			want: types.SBOM{
				OS: ftypes.OS{
					Family: "alpine",
					Name:   "3.16.0",
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
			inputFile: "testdata/sad/invalid-source-info.json",
			wantErr:   "failed to parse source info:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			v := &spdx.SPDX{SBOM: &types.SBOM{}}
			err = json.NewDecoder(f).Decode(v)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			// Not compare the SPDX field
			v.SPDX = nil

			sort.Slice(v.Applications, func(i, j int) bool {
				return v.Applications[i].Type < v.Applications[j].Type
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, *v.SBOM)
		})
	}
}
