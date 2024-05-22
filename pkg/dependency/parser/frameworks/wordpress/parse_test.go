package wordpress

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParseWordPress(t *testing.T) {
	tests := []struct {
		file    string // Test input file
		want    ftypes.Package
		wantErr string
	}{
		{
			file: "testdata/version.php",
			want: ftypes.Package{
				Name:    "wordpress",
				Version: "4.9.4-alpha",
			},
		},
		{
			file:    "testdata/versionFail.php",
			wantErr: "version.php could not be parsed",
		},
	}

	for _, tt := range tests {
		t.Run(path.Base(tt.file), func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)

			got, err := Parse(f)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
