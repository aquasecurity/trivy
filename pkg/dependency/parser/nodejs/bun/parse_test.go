package bun

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		file     string // Test input file
		want     []ftypes.Package
		wantDeps []ftypes.Dependency
		wantErr  string
	}{
		{
			name:     "normal",
			file:     "testdata/bun_happy.lock",
			want:     normalPkgs,
			wantDeps: normalDeps,
		},
		{
			name:    "invalid lockfile",
			file:    "testdata/bun_invalid.lock",
			wantErr: "JSON decode error",
		},
		{
			name:     "multiple workspaces",
			file:     "testdata/bun_multiple_ws.lock",
			want:     multipleWsPkgs,
			wantDeps: multipleWsDeps,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)
			defer f.Close()
			got, deps, err := NewParser().Parse(t.Context(), f)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			if tt.wantDeps != nil {
				assert.Equal(t, tt.wantDeps, deps)
			}
		})
	}
}
