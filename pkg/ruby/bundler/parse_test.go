package bundler

import (
	"os"
	"path"
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
			file: "testdata/Gemfile_normal.lock",
			want: BundlerNormal,
		},
		{
			file: "testdata/Gemfile_rails.lock",
			want: BundlerRails,
		},
		{
			file: "testdata/Gemfile_many.lock",
			want: BundlerMany,
		},
		{
			file: "testdata/Gemfile_rails7.lock",
			want: BundlerV2RailsV7,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			got, _, err := NewParser().Parse(f)
			require.NoError(t, err)

			assert.Equal(t, v.want, got)
		})
	}
}
