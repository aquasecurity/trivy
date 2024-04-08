package pipenv

import (
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/types"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file string // Test input file
		want []types.Library
	}{
		{
			file: "testdata/Pipfile_normal.lock",
			want: pipenvNormal,
		},
		{
			file: "testdata/Pipfile_django.lock",
			want: pipenvDjango,
		},
		{
			file: "testdata/Pipfile_many.lock",
			want: pipenvMany,
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
