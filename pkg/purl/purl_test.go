package purl

import (
	"testing"

	"github.com/aquasecurity/fanal/types"
	"github.com/package-url/packageurl-go"

	"github.com/stretchr/testify/assert"
)

func TestNewPackageURL(t *testing.T) {

	testCases := []struct {
		name string
		typ  string
		pkg  types.Package
		fos  *types.OS
		want packageurl.PackageURL
	}{
		{
			name: "maven package",
			typ:  "jar",
			pkg: types.Package{
				Name:    "org.springframework:spring-core",
				Version: "5.3.14",
			},
			want: packageurl.PackageURL{
				Type:      "maven",
				Namespace: "org.springframework",
				Name:      "spring-core",
				Version:   "5.3.14",
			},
		},
		{
			name: "yarn package",
			typ:  "yarn",
			pkg: types.Package{
				Name:    "@xtuc/ieee754",
				Version: "1.2.0",
			},
			want: packageurl.PackageURL{
				Type:      "npm",
				Namespace: "@xtuc",
				Name:      "ieee754",
				Version:   "1.2.0",
			},
		},
		{
			name: "yarn package with non-namespace",
			typ:  "yarn",
			pkg: types.Package{
				Name:    "lodash",
				Version: "4.17.21",
			},
			want: packageurl.PackageURL{
				Type:    "npm",
				Name:    "lodash",
				Version: "4.17.21",
			},
		},
		{
			name: "pypi package",
			typ:  "pip",
			pkg: types.Package{
				Name:    "Django_test",
				Version: "1.2.0",
			},
			want: packageurl.PackageURL{
				Type:    "pypi",
				Name:    "django-test",
				Version: "1.2.0",
			},
		},
		{
			name: "composer package",
			typ:  "composer",
			pkg: types.Package{
				Name:    "symfony/contracts",
				Version: "v1.0.2",
			},
			want: packageurl.PackageURL{
				Type:      "composer",
				Namespace: "symfony",
				Name:      "contracts",
				Version:   "v1.0.2",
			},
		},
		{
			name: "golang package",
			typ:  "gomod",
			pkg: types.Package{
				Name:    "github.com/go-sql-driver/Mysql",
				Version: "v1.5.0",
			},
			want: packageurl.PackageURL{
				Type:      "golang",
				Namespace: "github.com/go-sql-driver",
				Name:      "mysql",
				Version:   "v1.5.0",
			},
		},
		{
			name: "os package",
			typ:  "redhat",
			pkg: types.Package{
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
			fos: &types.OS{
				Family: "redhat",
				Name:   "8",
			},
			want: packageurl.PackageURL{
				Type:      "rpm",
				Namespace: "redhat",
				Name:      "acl",
				Version:   "2.2.53-1.el8",
				Qualifiers: packageurl.Qualifiers{
					{
						Key:   "arch",
						Value: "aarch64",
					},
					{
						Key:   "src_name",
						Value: "acl",
					},
					{
						Key:   "src_release",
						Value: "1.el8",
					},
					{
						Key:   "src_version",
						Value: "2.2.53",
					},
					{
						Key:   "distro",
						Value: "redhat-8",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			packageURL := NewPackageURL(tc.typ, tc.fos, tc.pkg)
			assert.Equal(t, tc.want, packageURL, tc.name)
		})
	}
}
