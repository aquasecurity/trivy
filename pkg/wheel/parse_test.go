package wheel

import (
	"os"
	"path"
	"testing"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file string // Test input file
		want []types.Library
	}{
		{
			file: "testdata/simple-0.1.0.METADATA",
			want: WheelSimple,
		},
		{
			file: "testdata/distlib-0.3.1.METADATA",
			want: WheelDistlib,
		},
		{
			file: "testdata/virtualenv-20.4.2.METADATA",
			want: WheelVirtualenv,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			got, err := Parse(f)
			require.NoError(t, err)

			assert.Equal(t, v.want, got)
		})
	}
}
