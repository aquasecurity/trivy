package purl_test

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/os"
	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestNewPackageURL(t *testing.T) {

	testCases := []struct {
		name     string
		typ      string
		pkg      ftypes.Package
		metadata types.Metadata
		want     packageurl.PackageURL
		wantErr  string
	}{
		{
			name: "maven package",
			typ:  string(analyzer.TypeJar),
			pkg: ftypes.Package{
				Name:    "org.springframework:spring-core",
				Version: "5.3.14",
			},
			want: packageurl.PackageURL{
				Type:      packageurl.TypeMaven,
				Namespace: "org.springframework",
				Name:      "spring-core",
				Version:   "5.3.14",
			},
		},
		{
			name: "yarn package",
			typ:  string(analyzer.TypeYarn),
			pkg: ftypes.Package{
				Name:    "@xtuc/ieee754",
				Version: "1.2.0",
			},
			want: packageurl.PackageURL{
				Type:      packageurl.TypeNPM,
				Namespace: "@xtuc",
				Name:      "ieee754",
				Version:   "1.2.0",
			},
		},
		{
			name: "yarn package with non-namespace",
			typ:  string(analyzer.TypeYarn),
			pkg: ftypes.Package{
				Name:    "lodash",
				Version: "4.17.21",
			},
			want: packageurl.PackageURL{
				Type:    packageurl.TypeNPM,
				Name:    "lodash",
				Version: "4.17.21",
			},
		},
		{
			name: "pypi package",
			typ:  string(analyzer.TypePip),
			pkg: ftypes.Package{
				Name:    "Django_test",
				Version: "1.2.0",
			},
			want: packageurl.PackageURL{
				Type:    packageurl.TypePyPi,
				Name:    "django-test",
				Version: "1.2.0",
			},
		},
		{
			name: "composer package",
			typ:  string(analyzer.TypeComposer),
			pkg: ftypes.Package{
				Name:    "symfony/contracts",
				Version: "v1.0.2",
			},
			want: packageurl.PackageURL{
				Type:      packageurl.TypeComposer,
				Namespace: "symfony",
				Name:      "contracts",
				Version:   "v1.0.2",
			},
		},
		{
			name: "golang package",
			typ:  string(analyzer.TypeGoMod),
			pkg: ftypes.Package{
				Name:    "github.com/go-sql-driver/Mysql",
				Version: "v1.5.0",
			},
			want: packageurl.PackageURL{
				Type:      packageurl.TypeGolang,
				Namespace: "github.com/go-sql-driver",
				Name:      "mysql",
				Version:   "v1.5.0",
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
			want: packageurl.PackageURL{
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
			want: packageurl.PackageURL{
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
			want: packageurl.PackageURL{
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
