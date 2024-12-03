package sum

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
		file string
		want []ftypes.Package
	}{
		{
			file: "testdata/gomod_normal.sum",
			want: GoModNormal,
		},
		{
			file: "testdata/gomod_emptyline.sum",
			want: GoModEmptyLine,
		},
		{
			file: "testdata/gomod_many.sum",
			want: GoModMany,
		},
		{
			file: "testdata/gomod_trivy.sum",
			want: GoModTrivy,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)
			defer f.Close()

			got, _, err := NewParser().Parse(f)
			require.NoError(t, err)

			for i := range got {
				got[i].ID = "" // Not compare IDs, tested in mod.TestModuleID()
			}

			sort.Sort(ftypes.Packages(got))
			sort.Sort(ftypes.Packages(v.want))

			assert.Equal(t, v.want, got)
		})
	}
}
