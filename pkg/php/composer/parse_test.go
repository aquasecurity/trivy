package composer

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
			file: "testdata/composer_normal.lock",
			want: ComposerNormal,
		},
		{
			file: "testdata/composer_laravel.lock",
			want: ComposerLaravel,
		},
		{
			file: "testdata/composer_symfony.lock",
			want: ComposerSymfony,
		},
		{
			file: "testdata/composer_with_dev.lock",
			want: ComposerWithDev,
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
