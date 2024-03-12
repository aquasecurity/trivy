package julia

import (
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		file     string // Test input file
		want     []types.Library
		wantDeps []types.Dependency
	}{
		{
			name:     "Manifest v1.6",
			file:     "testdata/primary/Manifest_v1.6.toml",
			want:     juliaV1_6Libs,
			wantDeps: juliaV1_6Deps,
		},
		{
			name:     "Manifest v1.8",
			file:     "testdata/primary/Manifest_v1.8.toml",
			want:     juliaV1_8Libs,
			wantDeps: juliaV1_8Deps,
		},
		{
			name:     "no deps v1.6",
			file:     "testdata/no_deps_v1.6/Manifest.toml",
			want:     nil,
			wantDeps: nil,
		},
		{
			name:     "no deps v1.9",
			file:     "testdata/no_deps_v1.9/Manifest.toml",
			want:     nil,
			wantDeps: nil,
		},
		{
			name:     "dep extensions v1.9",
			file:     "testdata/dep_ext_v1.9/Manifest.toml",
			want:     juliaV1_9DepExtLibs,
			wantDeps: nil,
		},
		{
			name:     "shadowed dep v1.9",
			file:     "testdata/shadowed_dep_v1.9/Manifest.toml",
			want:     juliaV1_9ShadowedDepLibs,
			wantDeps: juliaV1_9ShadowedDepDeps,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)

			gotLibs, gotDeps, err := NewParser().Parse(f)
			require.NoError(t, err)

			sort.Sort(types.Libraries(tt.want))
			assert.Equal(t, tt.want, gotLibs)
			if tt.wantDeps != nil {
				sort.Sort(types.Dependencies(tt.wantDeps))
				assert.Equal(t, tt.wantDeps, gotDeps)
			}
		})
	}
}
