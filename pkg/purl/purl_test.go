package purl

import (
	"testing"

	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report"

	"gotest.tools/assert"
)

func TestNewPackageURL(t *testing.T) {

	testCases := []struct {
		name  string
		typ   string
		pkg   types.Package
		class report.ResultClass
		fos   types.OS
		want  string
	}{
		{
			name:  "maven package",
			typ:   "jar",
			class: report.ClassLangPkg,
			pkg: types.Package{
				Name:    "org.springframework:spring-core",
				Version: "5.3.14",
			},
			want: "pkg:maven/org.springframework/spring-core@5.3.14",
		},
		{
			name:  "yarn package",
			typ:   "yarn",
			class: report.ClassLangPkg,
			pkg: types.Package{
				Name:    "@xtuc/ieee754",
				Version: "1.2.0",
			},
			want: "pkg:npm/%40xtuc/ieee754@1.2.0",
		},
		{
			name:  "pypi package",
			typ:   "pip",
			class: report.ClassLangPkg,
			pkg: types.Package{
				Name:    "Django_test",
				Version: "1.2.0",
			},
			want: "pkg:pypi/django-test@1.2.0",
		},
		{
			name:  "composer package",
			typ:   "composer",
			class: report.ClassLangPkg,
			pkg: types.Package{
				Name:    "symfony/contracts",
				Version: "v1.0.2",
			},
			want: "pkg:composer/symfony/contracts@v1.0.2",
		},
		{
			name:  "golang package",
			typ:   "gomod",
			class: report.ClassLangPkg,
			pkg: types.Package{
				Name:    "github.com/go-sql-driver/Mysql",
				Version: "v1.5.0",
			},
			want: "pkg:golang/github.com/go-sql-driver/mysql@v1.5.0",
		},
		{
			name:  "os package",
			typ:   "redhat",
			class: report.ClassOSPkg,
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
			fos: types.OS{
				Family: "redhat",
				Name:   "8",
			},
			want: "pkg:rpm/redhat/acl@2.2.53-1.el8?arch=aarch64&distro=8&src_name=acl&src_release=1.el8&src_version=2.2.53",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			packageURL := NewPackageURL(tc.typ, tc.class, tc.fos, tc.pkg)
			assert.Equal(t, tc.want, packageURL.ToString(), tc.name)
		})
	}
}
