package purl_test

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestNewPackageURL(t *testing.T) {
	testCases := []struct {
		name     string
		typ      ftypes.TargetType
		pkg      ftypes.Package
		metadata types.Metadata
		want     *purl.PackageURL
		wantErr  string
	}{
		{
			name: "maven package",
			typ:  ftypes.Jar,
			pkg: ftypes.Package{
				Name:    "org.springframework:spring-core",
				Version: "5.3.14",
			},
			want: &purl.PackageURL{
				Type:      packageurl.TypeMaven,
				Namespace: "org.springframework",
				Name:      "spring-core",
				Version:   "5.3.14",
			},
		},
		{
			name: "gradle package",
			typ:  ftypes.Gradle,
			pkg: ftypes.Package{
				Name:    "org.springframework:spring-core",
				Version: "5.3.14",
			},
			want: &purl.PackageURL{
				Type:      packageurl.TypeMaven,
				Namespace: "org.springframework",
				Name:      "spring-core",
				Version:   "5.3.14",
			},
		},
		{
			name: "sbt package",
			typ:  ftypes.Sbt,
			pkg: ftypes.Package{
				Name:    "org.typelevel:cats-core_2.12",
				Version: "2.9.0",
			},
			want: &purl.PackageURL{
				Type:      packageurl.TypeMaven,
				Namespace: "org.typelevel",
				Name:      "cats-core_2.12",
				Version:   "2.9.0",
			},
		},
		{
			name: "yarn package",
			typ:  ftypes.Yarn,
			pkg: ftypes.Package{
				Name:    "@xtuc/ieee754",
				Version: "1.2.0",
			},
			want: &purl.PackageURL{
				Type:      packageurl.TypeNPM,
				Namespace: "@xtuc",
				Name:      "ieee754",
				Version:   "1.2.0",
			},
		},
		{
			name: "yarn package with non-namespace",
			typ:  ftypes.Yarn,
			pkg: ftypes.Package{
				Name:    "lodash",
				Version: "4.17.21",
			},
			want: &purl.PackageURL{
				Type:    packageurl.TypeNPM,
				Name:    "lodash",
				Version: "4.17.21",
			},
		},
		{
			name: "pnpm package",
			typ:  ftypes.Pnpm,
			pkg: ftypes.Package{
				Name:    "@xtuc/ieee754",
				Version: "1.2.0",
			},
			want: &purl.PackageURL{
				Type:      packageurl.TypeNPM,
				Namespace: "@xtuc",
				Name:      "ieee754",
				Version:   "1.2.0",
			},
		},
		{
			name: "pnpm package with non-namespace",
			typ:  ftypes.Pnpm,
			pkg: ftypes.Package{
				Name:    "lodash",
				Version: "4.17.21",
			},
			want: &purl.PackageURL{
				Type:    packageurl.TypeNPM,
				Name:    "lodash",
				Version: "4.17.21",
			},
		},
		{
			name: "pypi package",
			typ:  ftypes.PythonPkg,
			pkg: ftypes.Package{
				Name:    "Django_test",
				Version: "1.2.0",
			},
			want: &purl.PackageURL{
				Type:    packageurl.TypePyPi,
				Name:    "django-test",
				Version: "1.2.0",
			},
		},
		{
			name: "conda package",
			typ:  ftypes.CondaPkg,
			pkg: ftypes.Package{
				Name:    "absl-py",
				Version: "0.4.1",
			},
			want: &purl.PackageURL{
				Type:    packageurl.TypeConda,
				Name:    "absl-py",
				Version: "0.4.1",
			},
		},
		{
			name: "conda environment.yaml",
			typ:  ftypes.CondaEnv,
			pkg: ftypes.Package{
				Name:    "blas",
				Version: "1.0",
			},
			want: &purl.PackageURL{
				Type:    packageurl.TypeConda,
				Name:    "blas",
				Version: "1.0",
			},
		},
		{
			name: "composer package",
			typ:  ftypes.Composer,
			pkg: ftypes.Package{
				Name:    "symfony/contracts",
				Version: "v1.0.2",
			},
			want: &purl.PackageURL{
				Type:      packageurl.TypeComposer,
				Namespace: "symfony",
				Name:      "contracts",
				Version:   "v1.0.2",
			},
		},
		{
			name: "golang package",
			typ:  ftypes.GoModule,
			pkg: ftypes.Package{
				Name:    "github.com/go-sql-driver/Mysql",
				Version: "v1.5.0",
			},
			want: &purl.PackageURL{
				Type:      packageurl.TypeGolang,
				Namespace: "github.com/go-sql-driver",
				Name:      "mysql",
				Version:   "v1.5.0",
			},
		},
		{
			name: "golang package with a local path",
			typ:  ftypes.GoModule,
			pkg: ftypes.Package{
				Name:    "./private_repos/cnrm.googlesource.com/cnrm/",
				Version: "",
			},
			want: nil,
		},
		{
			name: "hex package",
			typ:  ftypes.Hex,
			pkg: ftypes.Package{
				ID:      "bunt@0.2.0",
				Name:    "bunt",
				Version: "0.2.0",
				Locations: []ftypes.Location{
					{
						StartLine: 2,
						EndLine:   2,
					},
				},
			},
			want: &purl.PackageURL{
				Type:    packageurl.TypeHex,
				Name:    "bunt",
				Version: "0.2.0",
			},
		},
		{
			name: "dart package",
			typ:  ftypes.Pub,
			pkg: ftypes.Package{
				Name:    "http",
				Version: "0.13.2",
			},
			want: &purl.PackageURL{
				Type:    packageurl.TypePub,
				Name:    "http",
				Version: "0.13.2",
			},
		},
		{
			name: "swift package",
			typ:  ftypes.Swift,
			pkg: ftypes.Package{
				ID:      "github.com/apple/swift-atomics@1.1.0",
				Name:    "github.com/apple/swift-atomics",
				Version: "1.1.0",
			},
			want: &purl.PackageURL{
				Type:      packageurl.TypeSwift,
				Namespace: "github.com/apple",
				Name:      "swift-atomics",
				Version:   "1.1.0",
			},
		},
		{
			name: "cocoapods package",
			typ:  ftypes.Cocoapods,
			pkg: ftypes.Package{
				ID:      "GoogleUtilities/NSData+zlib@7.5.2",
				Name:    "GoogleUtilities/NSData+zlib",
				Version: "7.5.2",
			},
			want: &purl.PackageURL{
				Type:    packageurl.TypeCocoapods,
				Name:    "GoogleUtilities",
				Version: "7.5.2",
				Subpath: "NSData+zlib",
			},
		},
		{
			name: "rust binary",
			typ:  ftypes.RustBinary,
			pkg: ftypes.Package{
				ID:      "abomination@0.7.3",
				Name:    "abomination",
				Version: "0.7.3",
			},
			want: &purl.PackageURL{
				Type:    packageurl.TypeCargo,
				Name:    "abomination",
				Version: "0.7.3",
			},
		},
		{
			name: "dotnet Packages.props",
			typ:  ftypes.PackagesProps,
			pkg: ftypes.Package{
				ID:      "Newtonsoft.Json@9.0.1",
				Name:    "Newtonsoft.Json",
				Version: "9.0.1",
			},
			want: &purl.PackageURL{
				Type:    packageurl.TypeNuget,
				Name:    "Newtonsoft.Json",
				Version: "9.0.1",
			},
		},
		{
			name: "os package",
			typ:  ftypes.RedHat,
			pkg: ftypes.Package{
				Name:            "acl",
				Version:         "2.2.53",
				Release:         "1.el8",
				Epoch:           1,
				Arch:            "aarch64",
				SrcName:         "acl",
				SrcVersion:      "2.2.53",
				SrcRelease:      "1.el8",
				SrcEpoch:        1,
				Modularitylabel: "",
			},

			metadata: types.Metadata{
				OS: &ftypes.OS{
					Family: ftypes.RedHat,
					Name:   "8",
				},
			},
			want: &purl.PackageURL{
				Type:      packageurl.TypeRPM,
				Namespace: "redhat",
				Name:      "acl",
				Version:   "2.2.53-1.el8",
				Qualifiers: packageurl.Qualifiers{
					{
						Key:   "arch",
						Value: "aarch64",
					},
					{
						Key:   "epoch",
						Value: "1",
					},
					{
						Key:   "distro",
						Value: "redhat-8",
					},
				},
			},
		},
		{
			name: "container",
			typ:  purl.TypeOCI,
			metadata: types.Metadata{
				RepoTags: []string{
					"cblmariner2preview.azurecr.io/base/core:2.0.20220124-amd64",
				},
				RepoDigests: []string{
					"cblmariner2preview.azurecr.io/base/core@sha256:8fe1727132b2506c17ba0e1f6a6ed8a016bb1f5735e43b2738cd3fd1979b6260",
					"cblmariner2preview.azurecr.io/base/core@sha256:016bb1f5735e43b2738cd3fd1979b62608fe1727132b2506c17ba0e1f6a6ed8a",
				},
				ImageConfig: v1.ConfigFile{
					Architecture: "amd64",
				},
			},
			want: &purl.PackageURL{
				Type:      packageurl.TypeOCI,
				Namespace: "",
				Name:      "core",
				Version:   "sha256:8fe1727132b2506c17ba0e1f6a6ed8a016bb1f5735e43b2738cd3fd1979b6260",
				Qualifiers: packageurl.Qualifiers{
					{
						Key:   "repository_url",
						Value: "cblmariner2preview.azurecr.io/base/core",
					},
					{
						Key:   "arch",
						Value: "amd64",
					},
				},
			},
		},
		{
			name: "container local",
			typ:  purl.TypeOCI,
			metadata: types.Metadata{
				RepoTags:    []string{},
				RepoDigests: []string{},
				ImageConfig: v1.ConfigFile{
					Architecture: "amd64",
				},
				ImageID: "sha256:8fe1727132b2506c17ba0e1f6a6ed8a016bb1f5735e43b2738cd3fd1979b6260",
			},
			want: nil,
		},
		{
			name: "container with implicit registry",
			typ:  purl.TypeOCI,
			metadata: types.Metadata{
				RepoTags: []string{
					"alpine:3.14",
					"alpine:latest",
				},
				RepoDigests: []string{
					"alpine:3.14@sha256:8fe1727132b2506c17ba0e1f6a6ed8a016bb1f5735e43b2738cd3fd1979b6260",
					"alpine:latest@sha256:016bb1f5735e43b2738cd3fd1979b62608fe1727132b2506c17ba0e1f6a6ed8a",
				},
				ImageConfig: v1.ConfigFile{
					Architecture: "amd64",
				},
			},
			want: &purl.PackageURL{
				Type:      packageurl.TypeOCI,
				Namespace: "",
				Name:      "alpine",
				Version:   "sha256:8fe1727132b2506c17ba0e1f6a6ed8a016bb1f5735e43b2738cd3fd1979b6260",
				Qualifiers: packageurl.Qualifiers{
					{
						Key:   "repository_url",
						Value: "index.docker.io/library/alpine",
					},
					{
						Key:   "arch",
						Value: "amd64",
					},
				},
			},
		},
		{
			name: "sad path",
			typ:  purl.TypeOCI,
			metadata: types.Metadata{
				RepoTags: []string{
					"cblmariner2preview.azurecr.io/base/core:2.0.20220124-amd64",
				},
				RepoDigests: []string{
					"sha256:8fe1727132b2506c17ba0e1f6a6ed8a016bb1f5735e43b2738cd3fd1979b6260",
				},
			},
			wantErr: "failed to parse digest",
		},
		{
			name: "julia project",
			typ:  ftypes.Julia,
			pkg: ftypes.Package{
				ID:      "ade2ca70-3891-5945-98fb-dc099432e06a",
				Name:    "Dates",
				Version: "1.9.0",
			},
			want: &purl.PackageURL{
				Type:    packageurl.TypeJulia,
				Name:    "Dates",
				Version: "1.9.0",
				Qualifiers: packageurl.Qualifiers{
					{
						Key:   "uuid",
						Value: "ade2ca70-3891-5945-98fb-dc099432e06a",
					},
				},
			},
		},
		{
			name: "bottlerocket package",
			typ:  ftypes.Bottlerocket,
			metadata: types.Metadata{
				OS: &ftypes.OS{
					Family: ftypes.Bottlerocket,
					Name:   "1.34.0",
				},
			},
			pkg: ftypes.Package{
				ID:      "glibc@2.40",
				Name:    "glibc",
				Version: "2.40",
				Epoch:   1,
				Arch:    "x86_64",
			},
			want: &purl.PackageURL{
				Type:    "bottlerocket",
				Name:    "glibc",
				Version: "2.40",
				Qualifiers: packageurl.Qualifiers{
					{
						Key:   "arch",
						Value: "x86_64",
					},
					{
						Key:   "epoch",
						Value: "1",
					},
					{
						Key:   "distro",
						Value: "bottlerocket-1.34.0",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			packageURL, err := purl.New(tc.typ, tc.metadata, tc.pkg)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, packageURL, tc.name)
		})
	}
}

func TestFromString(t *testing.T) {
	testCases := []struct {
		name    string
		purl    string
		want    purl.PackageURL
		wantErr string
	}{
		{
			name: "happy path for maven",
			purl: "pkg:maven/org.springframework/spring-core@5.0.4.RELEASE",
			want: purl.PackageURL{
				Type:      packageurl.TypeMaven,
				Namespace: "org.springframework",
				Version:   "5.0.4.RELEASE",
				Name:      "spring-core",
			},
		},
		{
			name: "happy path for npm",
			purl: "pkg:npm/bootstrap@5.0.2",
			want: purl.PackageURL{
				Type:    packageurl.TypeNPM,
				Name:    "bootstrap",
				Version: "5.0.2",
			},
		},
		{
			name: "happy path for coocapods",
			purl: "pkg:cocoapods/GoogleUtilities@7.5.2#NSData+zlib",
			want: purl.PackageURL{
				Type:    packageurl.TypeCocoapods,
				Name:    "GoogleUtilities",
				Version: "7.5.2",
				Subpath: "NSData+zlib",
			},
		},
		{
			name: "happy path for hex",
			purl: "pkg:hex/plug@1.14.0",
			want: purl.PackageURL{
				Type:    packageurl.TypeHex,
				Name:    "plug",
				Version: "1.14.0",
			},
		},
		{
			name: "happy path for dart",
			purl: "pkg:pub/http@0.13.2",
			want: purl.PackageURL{
				Type:    packageurl.TypePub,
				Name:    "http",
				Version: "0.13.2",
			},
		},
		{
			name: "happy path for apk",
			purl: "pkg:apk/alpine/alpine-baselayout@3.2.0-r16?distro=3.14.2&epoch=1",
			want: purl.PackageURL{
				Type:      string(analyzer.TypeApk),
				Namespace: "alpine",
				Name:      "alpine-baselayout",
				Version:   "3.2.0-r16",
				Qualifiers: packageurl.Qualifiers{
					{
						Key:   "distro",
						Value: "3.14.2",
					},
					{
						Key:   "epoch",
						Value: "1",
					},
				},
			},
		},
		{
			name: "happy path for rpm",
			purl: "pkg:rpm/redhat/containers-common@0.1.14",
			want: purl.PackageURL{
				Type:      packageurl.TypeRPM,
				Namespace: "redhat",
				Name:      "containers-common",
				Version:   "0.1.14",
			},
		},
		{
			name: "happy path for conda",
			purl: "pkg:conda/absl-py@0.4.1",
			want: purl.PackageURL{
				Type:    packageurl.TypeConda,
				Name:    "absl-py",
				Version: "0.4.1",
			},
		},
		{
			name: "bad rpm",
			purl: "pkg:rpm/redhat/a--@1.0.0",
			want: purl.PackageURL{
				Type:      packageurl.TypeRPM,
				Namespace: "redhat",
				Name:      "a--",
				Version:   "1.0.0",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pkg, err := purl.FromString(tc.purl)
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, *pkg, tc.name)
		})
	}
}

func TestPackageURL_Package(t *testing.T) {
	tests := []struct {
		name    string
		pkgURL  *purl.PackageURL
		wantPkg *ftypes.Package
	}{
		{
			name: "rpm + Qualifiers",
			pkgURL: &purl.PackageURL{
				Type:      packageurl.TypeRPM,
				Namespace: "redhat",
				Name:      "nodejs-full-i18n",
				Version:   "10.21.0-3.module_el8.2.0+391+8da3adc6",
				Qualifiers: packageurl.Qualifiers{
					{
						Key:   "arch",
						Value: "x86_64",
					},
					{
						Key:   "epoch",
						Value: "1",
					},
					{
						Key:   "modularitylabel",
						Value: "nodejs:10:8020020200707141642:6a468ee4",
					},
					{
						Key:   "distro",
						Value: "redhat-8",
					},
				},
			},
			wantPkg: &ftypes.Package{
				ID:              "nodejs-full-i18n@10.21.0-3.module_el8.2.0+391+8da3adc6",
				Name:            "nodejs-full-i18n",
				Version:         "10.21.0",
				Release:         "3.module_el8.2.0+391+8da3adc6",
				Arch:            "x86_64",
				Epoch:           1,
				Modularitylabel: "nodejs:10:8020020200707141642:6a468ee4",
				Identifier: ftypes.PkgIdentifier{
					PURL: &packageurl.PackageURL{
						Type:      packageurl.TypeRPM,
						Namespace: "redhat",
						Name:      "nodejs-full-i18n",
						Version:   "10.21.0-3.module_el8.2.0+391+8da3adc6",
						Qualifiers: packageurl.Qualifiers{
							{
								Key:   "arch",
								Value: "x86_64",
							},
							{
								Key:   "epoch",
								Value: "1",
							},
							{
								Key:   "modularitylabel",
								Value: "nodejs:10:8020020200707141642:6a468ee4",
							},
							{
								Key:   "distro",
								Value: "redhat-8",
							},
						},
					},
				},
			},
		},
		{
			name: "composer with namespace",
			pkgURL: &purl.PackageURL{
				Type:      packageurl.TypeComposer,
				Namespace: "symfony",
				Name:      "contracts",
				Version:   "1.0.2",
			},

			wantPkg: &ftypes.Package{
				ID:      "symfony/contracts@1.0.2",
				Name:    "symfony/contracts",
				Version: "1.0.2",
				Identifier: ftypes.PkgIdentifier{
					PURL: &packageurl.PackageURL{
						Type:      packageurl.TypeComposer,
						Namespace: "symfony",
						Name:      "contracts",
						Version:   "1.0.2",
					},
				},
			},
		},
		{
			name: "maven with namespace",
			pkgURL: &purl.PackageURL{
				Type:      packageurl.TypeMaven,
				Namespace: "org.springframework",
				Name:      "spring-core",
				Version:   "5.0.4.RELEASE",
			},

			wantPkg: &ftypes.Package{
				ID:      "org.springframework:spring-core:5.0.4.RELEASE",
				Name:    "org.springframework:spring-core",
				Version: "5.0.4.RELEASE",
				Identifier: ftypes.PkgIdentifier{
					PURL: &packageurl.PackageURL{
						Type:      packageurl.TypeMaven,
						Namespace: "org.springframework",
						Name:      "spring-core",
						Version:   "5.0.4.RELEASE",
					},
				},
			},
		},
		{
			name: "cocoapods with subpath",
			pkgURL: &purl.PackageURL{
				Type:    packageurl.TypeCocoapods,
				Version: "4.2.0",
				Name:    "AppCenter",
				Subpath: "Analytics",
			},

			wantPkg: &ftypes.Package{
				ID:      "AppCenter/Analytics@4.2.0",
				Name:    "AppCenter/Analytics",
				Version: "4.2.0",
				Identifier: ftypes.PkgIdentifier{
					PURL: &packageurl.PackageURL{
						Type:    packageurl.TypeCocoapods,
						Version: "4.2.0",
						Name:    "AppCenter",
						Subpath: "Analytics",
					},
				},
			},
		},
		{
			name: "bottlerocket with epoch",
			pkgURL: &purl.PackageURL{
				Type:    "bottlerocket",
				Name:    "glibc",
				Version: "2.40",
				Qualifiers: packageurl.Qualifiers{
					{
						Key:   "epoch",
						Value: "1",
					},
					{
						Key:   "distro",
						Value: "bottlerocket-1.34.0",
					},
				},
			},
			wantPkg: &ftypes.Package{
				ID:      "glibc@2.40",
				Name:    "glibc",
				Version: "2.40",
				Epoch:   1,
				Identifier: ftypes.PkgIdentifier{
					PURL: &packageurl.PackageURL{
						Type:    "bottlerocket",
						Name:    "glibc",
						Version: "2.40",
						Qualifiers: packageurl.Qualifiers{
							{
								Key:   "epoch",
								Value: "1",
							},
							{
								Key:   "distro",
								Value: "bottlerocket-1.34.0",
							},
						},
					},
				},
			},
		},
		{
			name: "wrong epoch",
			pkgURL: &purl.PackageURL{
				Type:      packageurl.TypeRPM,
				Namespace: "redhat",
				Name:      "acl",
				Version:   "2.2.53-1.el8",
				Qualifiers: packageurl.Qualifiers{
					{
						Key:   "epoch",
						Value: "wrong",
					},
				},
			},
			wantPkg: &ftypes.Package{
				ID:      "acl@2.2.53-1.el8",
				Name:    "acl",
				Version: "2.2.53",
				Release: "1.el8",
				Identifier: ftypes.PkgIdentifier{
					PURL: &packageurl.PackageURL{
						Type:      packageurl.TypeRPM,
						Namespace: "redhat",
						Name:      "acl",
						Version:   "2.2.53-1.el8",
						Qualifiers: packageurl.Qualifiers{
							{
								Key:   "epoch",
								Value: "wrong",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.pkgURL.Package()
			assert.Equal(t, tt.wantPkg, got)
		})
	}
}

func TestPackageURL_LangType(t *testing.T) {
	tests := []struct {
		name string
		purl packageurl.PackageURL
		want ftypes.LangType
	}{
		{
			name: "maven",
			purl: packageurl.PackageURL{
				Type:      packageurl.TypeMaven,
				Namespace: "org.springframework",
				Name:      "spring-core",
				Version:   "5.0.4.RELEASE",
			},
			want: ftypes.Jar,
		},
		{
			name: "k8s",
			purl: packageurl.PackageURL{
				Type:    purl.TypeK8s,
				Name:    "kubelet",
				Version: "1.21.1",
			},
			want: ftypes.K8sUpstream,
		},
		{
			name: "eks",
			purl: packageurl.PackageURL{
				Type:      purl.TypeK8s,
				Namespace: purl.NamespaceEKS,
				Name:      "kubelet",
				Version:   "1.21.1",
			},
			want: ftypes.EKS,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := purl.PackageURL(tt.purl)
			assert.Equalf(t, tt.want, p.LangType(), "LangType()")
		})
	}
}

func TestPackageURL_Match(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		target     string
		want       bool
	}{
		{
			name:       "same purl",
			constraint: "pkg:golang/github.com/aquasecurity/trivy@v0.49.0",
			target:     "pkg:golang/github.com/aquasecurity/trivy@v0.49.0",
			want:       true,
		},
		{
			name:       "different type",
			constraint: "pkg:golang/github.com/aquasecurity/trivy@v0.49.0",
			target:     "pkg:maven/github.com/aquasecurity/trivy@0.49.0",
			want:       false,
		},
		{
			name:       "different namespace",
			constraint: "pkg:golang/github.com/aquasecurity/trivy@v0.49.0",
			target:     "pkg:golang/github.com/aquasecurity2/trivy@v.49.0",
			want:       false,
		},
		{
			name:       "different name",
			constraint: "pkg:golang/github.com/aquasecurity/trivy@v0.49.0",
			target:     "pkg:golang/github.com/aquasecurity/tracee@v0.49.0",
			want:       false,
		},
		{
			name:       "different version",
			constraint: "pkg:golang/github.com/aquasecurity/trivy@v0.49.0",
			target:     "pkg:golang/github.com/aquasecurity/trivy@v0.49.1",
			want:       false,
		},
		{
			name:       "version wildcard",
			constraint: "pkg:golang/github.com/aquasecurity/trivy",
			target:     "pkg:golang/github.com/aquasecurity/trivy@v0.50.0",
			want:       true,
		},
		{
			name:       "different qualifier",
			constraint: "pkg:bitnami/wordpress@6.2.0?arch=arm64&distro=debian-12",
			target:     "pkg:bitnami/wordpress@6.2.0?arch=arm64&distro=debian-13",
			want:       false,
		},
		{
			name:       "target more qualifiers",
			constraint: "pkg:bitnami/wordpress@6.2.0?arch=arm64",
			target:     "pkg:bitnami/wordpress@6.2.0?arch=arm64&distro=debian-13",
			want:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := purl.FromString(tt.constraint)
			require.NoError(t, err)

			p, err := purl.FromString(tt.target)
			require.NoError(t, err)

			assert.Equalf(t, tt.want, c.Match(p.Unwrap()), "Match()")
		})
	}
}
