package packaging

import (
	"testing"
	"testing/fstest"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

const (
	orjsonMetadataPath = "site-packages/orjson-3.13.0.dist-info/METADATA"
	orjsonSBOMPath     = "site-packages/orjson-3.13.0.dist-info/sboms/orjson.cyclonedx.json"
	orjsonMetadata     = "Metadata-Version: 2.4\nName: orjson\nVersion: 3.13.0\n"
)

var orjsonApp = types.Application{
	Type:     types.PythonPkg,
	FilePath: orjsonMetadataPath,
	Packages: types.Packages{
		{
			Name:     "orjson",
			Version:  "3.13.0",
			FilePath: orjsonMetadataPath,
		},
	},
}

func crate(sbomPath, name, version string, dependsOn ...string) types.Package {
	return types.Package{
		ID:      name + "@" + version,
		Name:    name,
		Version: version,
		Identifier: types.PkgIdentifier{
			PURL: &packageurl.PackageURL{
				Type:    packageurl.TypeCargo,
				Name:    name,
				Version: version,
			},
		},
		FilePath:  sbomPath,
		DependsOn: dependsOn,
	}
}

func Test_packagingAnalyzer_PEP770(t *testing.T) {
	tests := []struct {
		name  string
		files fstest.MapFS
		want  []types.Application
	}{
		{
			name: "crates are reported as a cargo application next to the Python package",
			files: fstest.MapFS{
				orjsonMetadataPath: {Data: []byte(orjsonMetadata)},
				orjsonSBOMPath: {Data: []byte(`{
					"bomFormat": "CycloneDX",
					"specVersion": "1.5",
					"components": [
						{
							"type": "library",
							"bom-ref": "registry+https://github.com/rust-lang/crates.io-index#pyo3-ffi@0.26.0",
							"name": "pyo3-ffi",
							"version": "0.26.0",
							"scope": "required",
							"licenses": [{"expression": "MIT OR Apache-2.0"}],
							"purl": "pkg:cargo/pyo3-ffi@0.26.0"
						},
						{
							"type": "library",
							"bom-ref": "registry+https://github.com/rust-lang/crates.io-index#libc@0.2.190",
							"name": "libc",
							"version": "0.2.190",
							"licenses": [{"license": {"id": "MIT"}}, {"license": {"name": "Custom"}}],
							"purl": "pkg:cargo/libc@0.2.190"
						}
					],
					"dependencies": [
						{
							"ref": "registry+https://github.com/rust-lang/crates.io-index#pyo3-ffi@0.26.0",
							"dependsOn": ["registry+https://github.com/rust-lang/crates.io-index#libc@0.2.190"]
						},
						{
							"ref": "registry+https://github.com/rust-lang/crates.io-index#libc@0.2.190",
							"dependsOn": []
						}
					]
				}`)},
			},
			want: []types.Application{
				orjsonApp,
				{
					Type:     types.Cargo,
					FilePath: orjsonSBOMPath,
					Packages: types.Packages{
						withLicenses(crate(orjsonSBOMPath, "libc", "0.2.190"), "MIT", "Custom"),
						withLicenses(crate(orjsonSBOMPath, "pyo3-ffi", "0.26.0", "libc@0.2.190"), "MIT OR Apache-2.0"),
					},
				},
			},
		},
		{
			name: "build dependencies are dropped",
			files: fstest.MapFS{
				orjsonMetadataPath: {Data: []byte(orjsonMetadata)},
				orjsonSBOMPath: {Data: []byte(`{
					"bomFormat": "CycloneDX",
					"specVersion": "1.5",
					"components": [
						{"type": "library", "bom-ref": "cc", "name": "cc", "version": "1.6.0", "scope": "excluded", "purl": "pkg:cargo/cc@1.6.0"},
						{"type": "library", "bom-ref": "shlex", "name": "shlex", "version": "1.3.0", "scope": "excluded", "purl": "pkg:cargo/shlex@1.3.0"},
						{"type": "library", "bom-ref": "libc", "name": "libc", "version": "0.2.190", "scope": "required", "purl": "pkg:cargo/libc@0.2.190"},
						{"type": "library", "bom-ref": "pyo3-ffi", "name": "pyo3-ffi", "version": "0.26.0", "scope": "required", "purl": "pkg:cargo/pyo3-ffi@0.26.0"}
					],
					"dependencies": [
						{"ref": "cc", "dependsOn": ["shlex", "libc"]},
						{"ref": "pyo3-ffi", "dependsOn": ["cc", "libc"]}
					]
				}`)},
			},
			want: []types.Application{
				orjsonApp,
				{
					Type:     types.Cargo,
					FilePath: orjsonSBOMPath,
					Packages: types.Packages{
						crate(orjsonSBOMPath, "libc", "0.2.190"),
						crate(orjsonSBOMPath, "pyo3-ffi", "0.26.0", "libc@0.2.190"),
					},
				},
			},
		},
		{
			name: "the root crate and workspace members are dropped",
			files: fstest.MapFS{
				orjsonMetadataPath: {Data: []byte(orjsonMetadata)},
				orjsonSBOMPath: {Data: []byte(`{
					"bomFormat": "CycloneDX",
					"specVersion": "1.5",
					"metadata": {
						"component": {"type": "library", "bom-ref": "orjson", "name": "orjson", "version": "3.13.0", "purl": "pkg:cargo/orjson@3.13.0?download_url=file://."}
					},
					"components": [
						{"type": "library", "bom-ref": "orjson-member", "name": "orjson-member", "version": "0.1.0", "scope": "required", "purl": "pkg:cargo/orjson-member@0.1.0?download_url=file://member"},
						{"type": "library", "bom-ref": "libc", "name": "libc", "version": "0.2.190", "scope": "required", "purl": "pkg:cargo/libc@0.2.190"}
					],
					"dependencies": [
						{"ref": "orjson", "dependsOn": ["orjson-member", "libc"]},
						{"ref": "orjson-member", "dependsOn": ["libc"]}
					]
				}`)},
			},
			want: []types.Application{
				orjsonApp,
				{
					Type:     types.Cargo,
					FilePath: orjsonSBOMPath,
					Packages: types.Packages{
						crate(orjsonSBOMPath, "libc", "0.2.190"),
					},
				},
			},
		},
		{
			name: "components other than crates are ignored",
			files: fstest.MapFS{
				orjsonMetadataPath: {Data: []byte(orjsonMetadata)},
				orjsonSBOMPath: {Data: []byte(`{
					"bomFormat": "CycloneDX",
					"specVersion": "1.5",
					"components": [
						{"type": "library", "bom-ref": "libgcc", "name": "libgcc", "version": "8.5.0-28.el8_10.alma.1", "purl": "pkg:rpm/almalinux/libgcc@8.5.0-28.el8_10.alma.1"},
						{"type": "library", "bom-ref": "vendored", "name": "vendored", "version": "1.0.0", "purl": "pkg:generic/vendored@1.0.0"},
						{"type": "library", "bom-ref": "no-purl", "name": "no-purl", "version": "1.0.0"},
						{"type": "library", "bom-ref": "bad-purl", "name": "bad-purl", "version": "1.0.0", "purl": "cargo/bad-purl"},
						{"type": "library", "bom-ref": "libc", "name": "libc", "version": "0.2.190", "purl": "pkg:cargo/libc@0.2.190"}
					],
					"dependencies": [
						{"ref": "libc", "dependsOn": ["libgcc", "unknown-ref"]},
						{"ref": "unknown-ref", "dependsOn": ["libc"]}
					]
				}`)},
			},
			want: []types.Application{
				orjsonApp,
				{
					Type:     types.Cargo,
					FilePath: orjsonSBOMPath,
					Packages: types.Packages{
						crate(orjsonSBOMPath, "libc", "0.2.190"),
					},
				},
			},
		},
		{
			name: "crates without a version are dropped",
			files: fstest.MapFS{
				orjsonMetadataPath: {Data: []byte(orjsonMetadata)},
				orjsonSBOMPath: {Data: []byte(`{
					"bomFormat": "CycloneDX",
					"specVersion": "1.5",
					"components": [
						{"type": "library", "bom-ref": "unversioned", "name": "unversioned", "purl": "pkg:cargo/unversioned"},
						{"type": "library", "bom-ref": "libc", "name": "libc", "version": "0.2.190", "purl": "pkg:cargo/libc@0.2.190"}
					],
					"dependencies": [
						{"ref": "libc", "dependsOn": ["unversioned"]}
					]
				}`)},
			},
			want: []types.Application{
				orjsonApp,
				{
					Type:     types.Cargo,
					FilePath: orjsonSBOMPath,
					Packages: types.Packages{
						crate(orjsonSBOMPath, "libc", "0.2.190"),
					},
				},
			},
		},
		{
			name: "a crate listed from two sources is reported once",
			files: fstest.MapFS{
				orjsonMetadataPath: {Data: []byte(orjsonMetadata)},
				orjsonSBOMPath: {Data: []byte(`{
					"bomFormat": "CycloneDX",
					"specVersion": "1.5",
					"components": [
						{"type": "library", "bom-ref": "registry+https://github.com/rust-lang/crates.io-index#libc@0.2.190", "name": "libc", "version": "0.2.190", "purl": "pkg:cargo/libc@0.2.190"},
						{"type": "library", "bom-ref": "git+https://github.com/rust-lang/libc#libc@0.2.190", "name": "libc", "version": "0.2.190", "purl": "pkg:cargo/libc@0.2.190"},
						{"type": "library", "bom-ref": "pyo3-ffi", "name": "pyo3-ffi", "version": "0.26.0", "purl": "pkg:cargo/pyo3-ffi@0.26.0"}
					],
					"dependencies": [
						{"ref": "pyo3-ffi", "dependsOn": ["registry+https://github.com/rust-lang/crates.io-index#libc@0.2.190", "git+https://github.com/rust-lang/libc#libc@0.2.190"]}
					]
				}`)},
			},
			want: []types.Application{
				orjsonApp,
				{
					Type:     types.Cargo,
					FilePath: orjsonSBOMPath,
					Packages: types.Packages{
						crate(orjsonSBOMPath, "libc", "0.2.190"),
						crate(orjsonSBOMPath, "pyo3-ffi", "0.26.0", "libc@0.2.190"),
					},
				},
			},
		},
		{
			name: "SBOM without crates adds no application",
			files: fstest.MapFS{
				orjsonMetadataPath: {Data: []byte(orjsonMetadata)},
				"site-packages/orjson-3.13.0.dist-info/sboms/auditwheel.cdx.json": {Data: []byte(`{
					"bomFormat": "CycloneDX",
					"specVersion": "1.4",
					"components": [
						{"type": "library", "bom-ref": "libgcc", "name": "libgcc", "version": "8.5.0-28.el8_10.alma.1", "purl": "pkg:rpm/almalinux/libgcc@8.5.0-28.el8_10.alma.1"}
					]
				}`)},
			},
			want: []types.Application{orjsonApp},
		},
		{
			name: "every SBOM of a wheel becomes its own application",
			files: fstest.MapFS{
				orjsonMetadataPath: {Data: []byte(orjsonMetadata)},
				orjsonSBOMPath: {Data: []byte(`{
					"bomFormat": "CycloneDX",
					"specVersion": "1.5",
					"components": [
						{"type": "library", "bom-ref": "libc", "name": "libc", "version": "0.2.190", "purl": "pkg:cargo/libc@0.2.190"}
					]
				}`)},
				"site-packages/orjson-3.13.0.dist-info/sboms/vendored.cdx.json": {Data: []byte(`{
					"bomFormat": "CycloneDX",
					"specVersion": "1.5",
					"components": [
						{"type": "library", "bom-ref": "libc", "name": "libc", "version": "0.2.190", "purl": "pkg:cargo/libc@0.2.190"}
					]
				}`)},
			},
			want: []types.Application{
				orjsonApp,
				{
					Type:     types.Cargo,
					FilePath: orjsonSBOMPath,
					Packages: types.Packages{
						crate(orjsonSBOMPath, "libc", "0.2.190"),
					},
				},
				{
					Type:     types.Cargo,
					FilePath: "site-packages/orjson-3.13.0.dist-info/sboms/vendored.cdx.json",
					Packages: types.Packages{
						crate("site-packages/orjson-3.13.0.dist-info/sboms/vendored.cdx.json", "libc", "0.2.190"),
					},
				},
			},
		},
		{
			name: "files that are not JSON SBOMs are skipped silently",
			files: fstest.MapFS{
				orjsonMetadataPath: {Data: []byte(orjsonMetadata)},
				"site-packages/orjson-3.13.0.dist-info/sboms/orjson.spdx":      {Data: []byte("SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\n")},
				"site-packages/orjson-3.13.0.dist-info/sboms/orjson.spdx.json": {Data: []byte(`{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": []}`)},
				"site-packages/orjson-3.13.0.dist-info/sboms/nested.json/orjson.cyclonedx.json": {Data: []byte(`{
					"bomFormat": "CycloneDX",
					"specVersion": "1.5",
					"components": [
						{"type": "library", "bom-ref": "libc", "name": "libc", "version": "0.2.190", "purl": "pkg:cargo/libc@0.2.190"}
					]
				}`)},
			},
			want: []types.Application{orjsonApp},
		},
		{
			name: "malformed SBOM does not hide the other results",
			files: fstest.MapFS{
				orjsonMetadataPath: {Data: []byte(orjsonMetadata)},
				"site-packages/orjson-3.13.0.dist-info/sboms/broken.cdx.json": {Data: []byte(`{"bomFormat": "CycloneDX", "components": [`)},
				orjsonSBOMPath: {Data: []byte(`{
					"bomFormat": "CycloneDX",
					"specVersion": "1.5",
					"components": [
						{"type": "library", "bom-ref": "libc", "name": "libc", "version": "0.2.190", "purl": "pkg:cargo/libc@0.2.190"}
					]
				}`)},
			},
			want: []types.Application{
				orjsonApp,
				{
					Type:     types.Cargo,
					FilePath: orjsonSBOMPath,
					Packages: types.Packages{
						crate(orjsonSBOMPath, "libc", "0.2.190"),
					},
				},
			},
		},
		{
			name: "sboms directory outside of dist-info is not read",
			files: fstest.MapFS{
				"site-packages/orjson-3.13.0.egg-info/METADATA": {Data: []byte(orjsonMetadata)},
				"site-packages/orjson-3.13.0.egg-info/sboms/orjson.cyclonedx.json": {Data: []byte(`{
					"bomFormat": "CycloneDX",
					"specVersion": "1.5",
					"components": [
						{"type": "library", "bom-ref": "libc", "name": "libc", "version": "0.2.190", "purl": "pkg:cargo/libc@0.2.190"}
					]
				}`)},
			},
			want: []types.Application{
				{
					Type:     types.PythonPkg,
					FilePath: "site-packages/orjson-3.13.0.egg-info/METADATA",
					Packages: types.Packages{
						{
							Name:     "orjson",
							Version:  "3.13.0",
							FilePath: "site-packages/orjson-3.13.0.egg-info/METADATA",
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newPackagingAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{FS: tt.files})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.Applications)
		})
	}
}

func withLicenses(pkg types.Package, licenses ...string) types.Package {
	pkg.Licenses = licenses
	return pkg
}
