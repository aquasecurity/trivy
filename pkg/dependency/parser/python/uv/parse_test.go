package uv

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		wantPkgs []ftypes.Package
		wantDeps []ftypes.Dependency
		wantErr  string
	}{
		{
			name:     "normal",
			file:     "testdata/uv_normal.lock",
			wantPkgs: uvNormal,
			wantDeps: uvNormalDeps,
		},
		{
			name:    "lockfile without root",
			file:    "testdata/uv_without_root.lock",
			wantErr: "uv lockfile must contain 1 root package",
		},
		{
			name:    "multiple roots",
			file:    "testdata/uv_multiple_roots.lock",
			wantErr: "uv lockfile must contain 1 root package",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)
			defer f.Close()

			p := NewParser()
			gotPkgs, gotDeps, err := p.Parse(f)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantPkgs, gotPkgs)
			assert.Equal(t, tt.wantDeps, gotDeps)
		})
	}
}
