package io_test

import (
	"context"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	sbomio "github.com/aquasecurity/trivy/pkg/sbom/io"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	apkToolsComponent = &core.Component{
		Type:    core.TypeLibrary,
		Name:    "apk-tools",
		Version: "2.14.10-r4",
		PkgIdentifier: ftypes.PkgIdentifier{
			PURL: &packageurl.PackageURL{
				Type:    packageurl.TypeApk,
				Name:    "apk-tools",
				Version: "2.14.10-r4",
				Qualifiers: packageurl.Qualifiers{
					{Key: "arch", Value: "aarch64"},
					{Key: "distro", Value: "wolfi-20230201"},
				},
			},
		},
		Licenses: []string{"GPL-2.0-only"},
	}

	busyboxComponent = &core.Component{
		Type:    core.TypeLibrary,
		Name:    "busybox",
		Version: "1.37.0-r42",
		PkgIdentifier: ftypes.PkgIdentifier{
			PURL: &packageurl.PackageURL{
				Type:    packageurl.TypeApk,
				Name:    "busybox",
				Version: "1.37.0-r42",
				Qualifiers: packageurl.Qualifiers{
					{Key: "arch", Value: "aarch64"},
					{Key: "distro", Value: "wolfi-20230201"},
				},
			},
		},
		Licenses: []string{"GPL-2.0-only"},
	}

	caCertificatesComponent = &core.Component{
		Type:    core.TypeLibrary,
		Name:    "ca-certificates-bundle",
		Version: "20241121-r42",
		PkgIdentifier: ftypes.PkgIdentifier{
			PURL: &packageurl.PackageURL{
				Type:    packageurl.TypeApk,
				Name:    "ca-certificates-bundle",
				Version: "20241121-r42",
				Qualifiers: packageurl.Qualifiers{
					{Key: "arch", Value: "aarch64"},
					{Key: "distro", Value: "wolfi-20230201"},
				},
			},
		},
		Licenses: []string{"MPL-2.0"},
	}

	wolfiOSComponent = &core.Component{
		Type:    core.TypeOS,
		Name:    "wolfi",
		Version: "20230201",
	}

	rpmTestComponent = &core.Component{
		Type:    core.TypeLibrary,
		Name:    "rpm-package",
		Version: "2.0.0",
		PkgIdentifier: ftypes.PkgIdentifier{
			PURL: &packageurl.PackageURL{
				Type:    packageurl.TypeRPM,
				Name:    "rpm-package",
				Version: "2.0.0",
			},
		},
		Licenses: []string{"GPL-2.0"},
	}
)

func TestDecoder_Decode_OSPackages(t *testing.T) {
	tests := []struct {
		name     string
		setupBOM func() *core.BOM
		wantSBOM types.SBOM
		wantErr  string
	}{
		{
			name: "OS packages with OS metadata should be included",
			setupBOM: func() *core.BOM {
				bom := core.NewBOM(core.Options{})
				bom.SerialNumber = "test-with-os"
				bom.Version = 1

				// Add OS component
				bom.AddComponent(wolfiOSComponent)

				// Add APK package
				bom.AddComponent(busyboxComponent)

				// Create relationship between OS and package
				bom.AddRelationship(wolfiOSComponent, busyboxComponent, core.RelationshipContains)
				return bom
			},
			wantSBOM: types.SBOM{
				Metadata: types.Metadata{
					OS: &ftypes.OS{
						Family: ftypes.Wolfi,
						Name:   "20230201",
					},
				},
				Packages: []ftypes.PackageInfo{
					{
						Packages: ftypes.Packages{
							{
								ID:         "busybox@1.37.0-r42",
								Name:       "busybox",
								Version:    "1.37.0-r42",
								Arch:       "aarch64",
								SrcName:    "busybox",
								SrcVersion: "1.37.0-r42",
								Licenses:   []string{"GPL-2.0-only"},
								Identifier: ftypes.PkgIdentifier{
									PURL: busyboxComponent.PkgIdentifier.PURL,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple OS packages without OS metadata should be included",
			setupBOM: func() *core.BOM {
				bom := core.NewBOM(core.Options{})
				bom.SerialNumber = "test-multiple-no-os"
				bom.Version = 1

				// Add multiple APK packages
				bom.AddComponent(apkToolsComponent)
				bom.AddComponent(busyboxComponent)
				bom.AddComponent(caCertificatesComponent)

				return bom
			},
			wantSBOM: types.SBOM{
				Metadata: types.Metadata{
					OS: nil, // No OS detected
				},
				Packages: []ftypes.PackageInfo{
					{
						Packages: ftypes.Packages{
							{
								ID:         "apk-tools@2.14.10-r4",
								Name:       "apk-tools",
								Version:    "2.14.10-r4",
								Arch:       "aarch64",
								SrcName:    "apk-tools",
								SrcVersion: "2.14.10-r4",
								Licenses:   []string{"GPL-2.0-only"},
								Identifier: ftypes.PkgIdentifier{
									PURL: apkToolsComponent.PkgIdentifier.PURL,
								},
							},
							{
								ID:         "busybox@1.37.0-r42",
								Name:       "busybox",
								Version:    "1.37.0-r42",
								Arch:       "aarch64",
								SrcName:    "busybox",
								SrcVersion: "1.37.0-r42",
								Licenses:   []string{"GPL-2.0-only"},
								Identifier: ftypes.PkgIdentifier{
									PURL: busyboxComponent.PkgIdentifier.PURL,
								},
							},
							{
								ID:         "ca-certificates-bundle@20241121-r42",
								Name:       "ca-certificates-bundle",
								Version:    "20241121-r42",
								Arch:       "aarch64",
								SrcName:    "ca-certificates-bundle",
								SrcVersion: "20241121-r42",
								Licenses:   []string{"MPL-2.0"},
								Identifier: ftypes.PkgIdentifier{
									PURL: caCertificatesComponent.PkgIdentifier.PURL,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple OS package types should return error",
			setupBOM: func() *core.BOM {
				bom := core.NewBOM(core.Options{})
				bom.SerialNumber = "test-multiple-os-types"
				bom.Version = 1

				// Add APK package
				bom.AddComponent(apkToolsComponent)

				// Add RPM package
				bom.AddComponent(rpmTestComponent)

				return bom
			},
			wantErr: "multiple types of OS packages in SBOM are not supported",
		},
		{
			name: "empty BOM should have no packages",
			setupBOM: func() *core.BOM {
				bom := core.NewBOM(core.Options{})
				bom.SerialNumber = "test-empty"
				bom.Version = 1
				return bom
			},
			wantSBOM: types.SBOM{
				Metadata: types.Metadata{
					OS: nil,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bom := tt.setupBOM()
			decoder := sbomio.NewDecoder(bom)
			var gotSBOM types.SBOM

			err := decoder.Decode(context.Background(), &gotSBOM)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			// Set BOM for comparison (it's set by the decoder)
			tt.wantSBOM.BOM = gotSBOM.BOM

			// Compare the entire SBOM structure
			assert.Equal(t, tt.wantSBOM, gotSBOM)
		})
	}
}