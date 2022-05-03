package yarn

import (
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
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
		actual, _, err := parsePackageLocator(v.target)

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
		file string // Test input file
		want []types.Library
	}{
		{
			file: "testdata/yarn_normal.lock",
			want: yarnNormal,
		},
		{
			file: "testdata/yarn_react.lock",
			want: yarnReact,
		},
		{
			file: "testdata/yarn_with_dev.lock",
			want: yarnWithDev,
		},
		{
			file: "testdata/yarn_many.lock",
			want: yarnMany,
		},
		{
			file: "testdata/yarn_realworld.lock",
			want: yarnRealWorld,
		},
		{
			file: "testdata/yarn_with_npm.lock",
			want: yarnWithNpm,
		},
		{
			file: "testdata/yarn_v2_normal.lock",
			want: yarnV2Normal,
		},
		{
			file: "testdata/yarn_v2_react.lock",
			want: yarnV2React,
		},
		{
			file: "testdata/yarn_v2_with_dev.lock",
			want: yarnV2WithDev,
		},
		{
			file: "testdata/yarn_v2_many.lock",
			want: yarnV2Many,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			got, _, err := NewParser().Parse(f)
			require.NoError(t, err)

			sort.Slice(got, func(i, j int) bool {
				ret := strings.Compare(got[i].Name, got[j].Name)
				if ret == 0 {
					return got[i].Version < got[j].Version
				}
				return ret < 0
			})

			sort.Slice(v.want, func(i, j int) bool {
				ret := strings.Compare(v.want[i].Name, v.want[j].Name)
				if ret == 0 {
					return v.want[i].Version < v.want[j].Version
				}
				return ret < 0
			})

			assert.Equal(t, v.want, got)
		})
	}
}
