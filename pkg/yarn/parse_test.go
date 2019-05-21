package yarn

import (
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/knqyf263/go-dep-parser/pkg/types"
	"github.com/kylelemons/godebug/pretty"
)

func TestGetPackageName(t *testing.T) {
	vectors := []struct {
		target   string // Test input file
		expect   string
		occurErr bool
	}{
		{
			target: `"@babel/code-frame@^7.0.0"`,
			expect: "@babel/code-frame",
		},
		{
			target: `grunt-contrib-cssmin@3.0.*:`,
			expect: "grunt-contrib-cssmin",
		},
		{
			target: "grunt-contrib-uglify-es@gruntjs/grunt-contrib-uglify#harmony:",
			expect: "grunt-contrib-uglify-es",
		},
		{
			target: `"jquery@git+https://xxxx:x-oauth-basic@github.com/tomoyamachi/jquery":`,
			expect: "jquery",
		},
		{
			target:   `normal line`,
			occurErr: true,
		},
	}

	for _, v := range vectors {
		actual, err := getPackageName(v.target)

		if v.occurErr != (err != nil) {
			t.Errorf("expect error %t but err is %s", v.occurErr, err)
			continue
		}

		if actual != v.expect {
			t.Errorf("got %s, want %s, target :%s", actual, v.expect, v.target)
		}
	}
}

func TestParse(t *testing.T) {
	vectors := []struct {
		file      string // Test input file
		libraries []types.Library
	}{
		{
			file:      "testdata/yarn_normal.lock",
			libraries: YarnNormal,
		},
		{
			file:      "testdata/yarn_react.lock",
			libraries: YarnReact,
		},
		{
			file:      "testdata/yarn_with_dev.lock",
			libraries: YarnWithDev,
		},
		{
			file:      "testdata/yarn_many.lock",
			libraries: YarnMany,
		},
		{
			file:      "testdata/yarn_realworld.lock",
			libraries: YarnRealWorld,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			if err != nil {
				t.Fatalf("Open() error: %v", err)
			}
			libList, err := Parse(f)
			if err != nil {
				t.Fatalf("Parse() error: %v", err)
			}

			sort.Slice(libList, func(i, j int) bool {
				ret := strings.Compare(libList[i].Name, libList[j].Name)
				if ret == 0 {
					return libList[i].Version < libList[j].Version
				}
				return ret < 0
			})

			sort.Slice(v.libraries, func(i, j int) bool {
				ret := strings.Compare(v.libraries[i].Name, v.libraries[j].Name)
				if ret == 0 {
					return v.libraries[i].Version < v.libraries[j].Version
				}
				return ret < 0
			})

			if len(libList) != len(v.libraries) {
				t.Fatalf("lib length: %s", pretty.Compare(libList, v.libraries))
			}

			for i, got := range libList {
				want := v.libraries[i]
				if want.Name != got.Name {
					t.Errorf("%d: Name: got %s, want %s", i, got.Name, want.Name)
				}
				if want.Version != got.Version {
					t.Errorf("%d: Version: got %s, want %s", i, got.Version, want.Version)
				}
			}
		})
	}
}
