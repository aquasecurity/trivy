package pipenv

import (
	"os"
	"path"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file string // Test input file
		want []ftypes.Package
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

			sort.Sort(ftypes.Packages(got))
			sort.Sort(ftypes.Packages(v.want))

			assert.Equal(t, v.want, got)
		})
	}
}
