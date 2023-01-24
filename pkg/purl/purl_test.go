package purl_test

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestNewPackageURL(t *testing.T) {

	testCases := []struct {
		name     string
		typ      string
		pkg      ftypes.Package
		metadata types.Metadata
		want     purl.PackageURL
		wantErr  string
	}{
		{
			name: "maven package",
			typ:  ftypes.Jar,
			pkg: ftypes.Package{
				Name:    "org.springframework:spring-core",
				Version: "5.3.14",
			},
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      packageurl.TypeMaven,
					Namespace: "org.springframework",
					Name:      "spring-core",
					Version:   "5.3.14",
				},
			},
		},
		{
			name: "gradle package",
			typ:  ftypes.Gradle,
			pkg: ftypes.Package{
				Name:    "org.springframework:spring-core",
				Version: "5.3.14",
			},
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      packageurl.TypeMaven,
					Namespace: "org.springframework",
					Name:      "spring-core",
					Version:   "5.3.14",
				},
			},
		},
		{
			name: "yarn package",
			typ:  ftypes.Yarn,
			pkg: ftypes.Package{
				Name:    "@xtuc/ieee754",
				Version: "1.2.0",
			},
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      packageurl.TypeNPM,
					Namespace: "@xtuc",
					Name:      "ieee754",
					Version:   "1.2.0",
				},
			},
		},
		{
			name: "yarn package with non-namespace",
			typ:  ftypes.Yarn,
			pkg: ftypes.Package{
				Name:    "lodash",
				Version: "4.17.21",
			},
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:    packageurl.TypeNPM,
					Name:    "lodash",
					Version: "4.17.21",
				},
			},
		},
		{
			name: "pnpm package",
			typ:  ftypes.Pnpm,
			pkg: ftypes.Package{
				Name:    "@xtuc/ieee754",
				Version: "1.2.0",
			},
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      packageurl.TypeNPM,
					Namespace: "@xtuc",
					Name:      "ieee754",
					Version:   "1.2.0",
				},
			},
		},
		{
			name: "pnpm package with non-namespace",
			typ:  ftypes.Pnpm,
			pkg: ftypes.Package{
				Name:    "lodash",
				Version: "4.17.21",
			},
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:    packageurl.TypeNPM,
					Name:    "lodash",
					Version: "4.17.21",
				},
			},
		},
		{
			name: "pypi package",
			typ:  ftypes.PythonPkg,
			pkg: ftypes.Package{
				Name:    "Django_test",
				Version: "1.2.0",
			},
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:    packageurl.TypePyPi,
					Name:    "django-test",
					Version: "1.2.0",
				},
			},
		},
		{
			name: "conda package",
			typ:  ftypes.CondaPkg,
			pkg: ftypes.Package{
				Name:    "absl-py",
				Version: "0.4.1",
			},
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:    packageurl.TypeConda,
					Name:    "absl-py",
					Version: "0.4.1",
				},
			},
		},
		{
			name: "composer package",
			typ:  ftypes.Composer,
			pkg: ftypes.Package{
				Name:    "symfony/contracts",
				Version: "v1.0.2",
			},
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      packageurl.TypeComposer,
					Namespace: "symfony",
					Name:      "contracts",
					Version:   "v1.0.2",
				},
			},
		},
		{
			name: "golang package",
			typ:  ftypes.GoModule,
			pkg: ftypes.Package{
				Name:    "github.com/go-sql-driver/Mysql",
				Version: "v1.5.0",
			},
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      packageurl.TypeGolang,
					Namespace: "github.com/go-sql-driver",
					Name:      "mysql",
					Version:   "v1.5.0",
				},
			},
		},
		{
			name: "hex package",
			typ:  ftypes.Hex,
			pkg: ftypes.Package{
				ID:        "bunt@0.2.0",
				Name:      "bunt",
				Version:   "0.2.0",
				Locations: []ftypes.Location{{StartLine: 2, EndLine: 2}},
			},
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:    packageurl.TypeHex,
					Name:    "bunt",
					Version: "0.2.0",
				},
			},
		},
		{
			name: "dart package",
			typ:  ftypes.Pub,
			pkg: ftypes.Package{
				Name:    "http",
				Version: "0.13.2",
			},
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:    purl.TypeDart,
					Name:    "http",
					Version: "0.13.2",
				},
			},
		},
		{
			name: "os package",
			typ:  os.RedHat,
			pkg: ftypes.Package{
				Name:            "acl",
				Version:         "2.2.53",
				Release:         "1.el8",
				Epoch:           0,
				Arch:            "aarch64",
				SrcName:         "acl",
				SrcVersion:      "2.2.53",
				SrcRelease:      "1.el8",
				SrcEpoch:        0,
				Modularitylabel: "",
			},

			metadata: types.Metadata{
				OS: &ftypes.OS{
					Family: os.RedHat,
					Name:   "8",
				},
			},
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
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
							Key:   "distro",
							Value: "redhat-8",
						},
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
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
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
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      "",
					Namespace: "",
					Name:      "",
					Version:   "",
				},
			},
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
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			packageURL, err := purl.NewPackageURL(tc.typ, tc.metadata, tc.pkg)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			assert.NoError(t, err)
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
				PackageURL: packageurl.PackageURL{
					Type:       packageurl.TypeMaven,
					Namespace:  "org.springframework",
					Version:    "5.0.4.RELEASE",
					Name:       "spring-core",
					Qualifiers: packageurl.Qualifiers{},
				},
				FilePath: "",
			},
		},
		{
			name: "happy path for npm",
			purl: "pkg:npm/bootstrap@5.0.2?file_path=app%2Fapp%2Fpackage.json",
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:    packageurl.TypeNPM,
					Name:    "bootstrap",
					Version: "5.0.2",
					Qualifiers: packageurl.Qualifiers{
						{
							Key:   "file_path",
							Value: "app/app/package.json",
						},
					},
				},
			},
		},
		{
			name: "happy path for hex",
			purl: "pkg:hex/plug@1.14.0",
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:       packageurl.TypeHex,
					Name:       "plug",
					Version:    "1.14.0",
					Qualifiers: packageurl.Qualifiers{},
				},
			},
		},
		{
			name: "happy path for dart",
			purl: "pkg:dart/http@0.13.2",
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:       purl.TypeDart,
					Name:       "http",
					Version:    "0.13.2",
					Qualifiers: packageurl.Qualifiers{},
				},
			},
		},
		{
			name: "happy path for apk",
			purl: "pkg:apk/alpine/alpine-baselayout@3.2.0-r16?distro=3.14.2",
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      string(analyzer.TypeApk),
					Namespace: "alpine",
					Name:      "alpine-baselayout",
					Version:   "3.2.0-r16",
					Qualifiers: packageurl.Qualifiers{
						{
							Key:   "distro",
							Value: "3.14.2",
						},
					},
				},
			},
		},
		{
			name: "happy path for rpm",
			purl: "pkg:rpm/redhat/containers-common@0.1.14",
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:       packageurl.TypeRPM,
					Namespace:  "redhat",
					Name:       "containers-common",
					Version:    "0.1.14",
					Qualifiers: packageurl.Qualifiers{},
				},
			},
		},
		{
			name: "happy path for conda",
			purl: "pkg:conda/absl-py@0.4.1",
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:       packageurl.TypeConda,
					Name:       "absl-py",
					Version:    "0.4.1",
					Qualifiers: packageurl.Qualifiers{},
				},
			},
		},
		{
			name: "bad rpm",
			purl: "pkg:rpm/redhat/a--@1.0.0",
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:       packageurl.TypeRPM,
					Namespace:  "redhat",
					Name:       "a--",
					Version:    "1.0.0",
					Qualifiers: packageurl.Qualifiers{},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pkg, err := purl.FromString(tc.purl)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, *pkg, tc.name)
		})
	}
}
