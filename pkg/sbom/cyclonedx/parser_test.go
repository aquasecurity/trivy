package cyclonedx_test

import (
	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestParser_Parse(t *testing.T) {

	type want struct {
		bomRef   string
		OS       *ftypes.OS
		pkgInfos []ftypes.PackageInfo
		apps     []ftypes.Application
	}

	tests := []struct {
		name      string
		inputFile string
		want      want
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy/bom.json",
			want: want{
				bomRef: "urn:uuid:c986ba94-e37d-49c8-9e30-96daccd0415b",
				OS: &ftypes.OS{
					Family: "alpine",
					Name:   "3.16.0",
				},
				pkgInfos: []ftypes.PackageInfo{
					{
						Packages: []ftypes.Package{
							{
								Name: "musl", Version: "1.2.3-r0", SrcName: "musl", SrcVersion: "1.2.3-r0", License: "MIT",
								Ref: "pkg:apk/alpine/musl@1.2.3-r0?distro=3.16.0",
								Layer: ftypes.Layer{
									DiffID: "sha256:dd565ff850e7003356e2b252758f9bdc1ff2803f61e995e24c7844f6297f8fc3",
								},
							},
						},
					},
				},
				apps: []ftypes.Application{
					{
						Type:     "composer",
						FilePath: "app/composer/composer.lock",
						Libraries: []ftypes.Package{
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
						Libraries: []ftypes.Package{
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
						Type:     "jar",
						FilePath: "app/maven/target/child-project-1.0.jar",
						Libraries: []ftypes.Package{
							{
								Name:    "org.codehaus.mojo:child-project",
								Ref:     "pkg:maven/org.codehaus.mojo/child-project@1.0?file_path=app%2Fmaven%2Ftarget%2Fchild-project-1.0.jar",
								Version: "1.0",
								Layer: ftypes.Layer{
									DiffID: "sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
								},
							},
						},
					},
					{
						Type:     "node-pkg",
						FilePath: "app/app/package.json",
						Libraries: []ftypes.Package{
							{
								Name:    "bootstrap",
								Version: "5.0.2",
								Ref:     "pkg:npm/bootstrap@5.0.2?file_path=app%2Fapp%2Fpackage.json",
								License: "MIT",
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
			name:      "happy path for unrelated bom",
			inputFile: "testdata/happy/unrelated-bom.json",
			want: want{
				bomRef: "urn:uuid:c986ba94-e37d-49c8-9e30-96daccd0415b",
				apps: []ftypes.Application{
					{
						Type:     "composer",
						FilePath: "app/composer/composer.lock",
						Libraries: []ftypes.Package{
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
			name:      "happy path for independent library bom",
			inputFile: "testdata/happy/independent-library-bom.json",
			want: want{
				bomRef: "urn:uuid:c986ba94-e37d-49c8-9e30-96daccd0415b",
				apps: []ftypes.Application{
					{
						Type:     "composer",
						FilePath: "composer",
						Libraries: []ftypes.Package{
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
			name:      "happy path only os component",
			inputFile: "testdata/happy/os-only-bom.json",
			want: want{
				bomRef: "urn:uuid:c986ba94-e37d-49c8-9e30-96daccd0415b",
				OS: &ftypes.OS{
					Family: "alpine",
					Name:   "3.16.0",
				},
			},
		},
		{
			name:      "happy path empty component",
			inputFile: "testdata/happy/empty-bom.json",
			want: want{
				bomRef: "urn:uuid:c986ba94-e37d-49c8-9e30-96daccd0415b",
			},
		},
		{
			name:      "sad path invalid purl",
			inputFile: "testdata/sad/invalid-purl.json",
			wantErr:   "failed to parse purl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := cyclonedx.NewParser(tt.inputFile)
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)

			bomRef, OS, pkgInfos, apps, err := parser.Parse(f)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want.bomRef, bomRef)
			assert.Equal(t, tt.want.OS, OS)
			assert.Equal(t, tt.want.pkgInfos, pkgInfos)
			assert.Equal(t, tt.want.apps, apps)
		})
	}
}
