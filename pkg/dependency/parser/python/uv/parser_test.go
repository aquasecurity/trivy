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
	}{
		{
			name:     "normal",
			file:     "testdata/uv_normal.lock",
			wantPkgs: uvNormal,
			wantDeps: uvNormalDeps,
		},
		{
			name:     "many",
			file:     "testdata/uv_large.lock",
			wantPkgs: uvLarge,
			wantDeps: uvLargeDeps,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)
			defer f.Close()

			p := New()
			gotPkgs, gotDeps, err := p.Parse(f)
			require.NoError(t, err)
			assert.Equal(t, tt.wantPkgs, gotPkgs)
			assert.Equal(t, tt.wantDeps, gotDeps)
		})
	}
}
