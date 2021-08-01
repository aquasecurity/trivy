package npm

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

func TestParse(t *testing.T) {
	vectors := []struct {
		file string // Test input file
		want []types.Library
	}{
		{
			file: "testdata/package-lock_normal.json",
			want: npmNormal,
		},
		{
			file: "testdata/package-lock_react.json",
			want: npmReact,
		},
		{
			file: "testdata/package-lock_with_dev.json",
			want: npmWithDev,
		},
		{
			file: "testdata/package-lock_many.json",
			want: npmMany,
		},
		{
			file: "testdata/package-lock_nested.json",
			want: npmNested,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			got, err := Parse(f)
			require.NoError(t, err)

			sortLibs(got)
			sortLibs(v.want)

			assert.Equal(t, v.want, got)
		})
	}
}

func sortLibs(libs []types.Library) {
	sort.Slice(libs, func(i, j int) bool {
		ret := strings.Compare(libs[i].Name, libs[j].Name)
		if ret == 0 {
			return libs[i].Version < libs[j].Version
		}
		return ret < 0
	})
}
