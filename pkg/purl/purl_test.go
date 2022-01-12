package purl

import (
	"testing"

	"github.com/aquasecurity/fanal/types"

	"gotest.tools/assert"
)

func TestNewPackageURL(t *testing.T) {

	testCases := []struct {
		name string
		typ  string
		pkg  types.Package
		want string
	}{
		{
			name: "maven package",
			typ:  "jar",
			pkg: types.Package{
				Name:    "org.springframework:spring-core",
				Version: "5.3.14",
			},
			want: "pkg:maven/org.springframework/spring-core@5.3.14",
		},
		{
			name: "language package",
			typ:  "yarn",
			pkg: types.Package{
				Name:    "@xtuc/ieee754",
				Version: "1.2.0",
			},
			want: "pkg:npm/%40xtuc/ieee754@1.2.0",
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
			want: "pkg:rpm/acl@2.2.53?release=1.el8&arch=aarch64&src_name=acl&src_version=2.2.53&src_release=1.el8",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			packageURL := NewPackageURL(tc.typ, tc.pkg)
			assert.Equal(t, tc.want, packageURL.ToString(), tc.name)
		})
	}
}
