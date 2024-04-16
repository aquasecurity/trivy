package binary_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/rust/binary"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
)

// Test binaries generated from cargo-auditable test fixture
// https://github.com/rust-secure-code/cargo-auditable/tree/6b77151/cargo-auditable/tests/fixtures/workspace
var (
	libs = []types.Library{
		{
			ID:       "crate_with_features@0.1.0",
			Name:     "crate_with_features",
			Version:  "0.1.0",
			Indirect: false,
		},
		{
			ID:       "library_crate@0.1.0",
			Name:     "library_crate",
			Version:  "0.1.0",
			Indirect: true,
		},
	}

	deps = []types.Dependency{
		{
			ID:        "crate_with_features@0.1.0",
			DependsOn: []string{"library_crate@0.1.0"},
		},
	}
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      []types.Library
		wantDeps  []types.Dependency
		wantErr   string
	}{
		{
			name:      "ELF",
			inputFile: "testdata/test.elf",
			want:      libs,
			wantDeps:  deps,
		},
		{
			name:      "PE",
			inputFile: "testdata/test.exe",
			want:      libs,
			wantDeps:  deps,
		},
		{
			name:      "Mach-O",
			inputFile: "testdata/test.macho",
			want:      libs,
			wantDeps:  deps,
		},
		{
			name:      "sad path",
			inputFile: "testdata/dummy",
			wantErr:   "unrecognized executable format",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			got, gotDeps, err := binary.NewParser().Parse(f)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantDeps, gotDeps)
		})
	}
}
