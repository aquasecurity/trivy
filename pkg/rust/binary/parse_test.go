package binary_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/rust/binary"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

// Test binaries generated from cargo-auditable test fixture
// https://github.com/rust-secure-code/cargo-auditable/tree/6b77151/cargo-auditable/tests/fixtures/workspace

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      []types.Library
		wantErr   string
	}{
		{
			name:      "ELF",
			inputFile: "testdata/test.elf",
			want: []types.Library{
				{
					Name:    "crate_with_features",
					Version: "0.1.0",
				},
				{
					Name:    "library_crate",
					Version: "0.1.0",
				},
			},
		},
		{
			name:      "PE",
			inputFile: "testdata/test.exe",
			want: []types.Library{
				{
					Name:    "crate_with_features",
					Version: "0.1.0",
				},
				{
					Name:    "library_crate",
					Version: "0.1.0",
				},
			},
		},
		{
			name:      "Mach-O",
			inputFile: "testdata/test.macho",
			want: []types.Library{
				{
					Name:    "crate_with_features",
					Version: "0.1.0",
				},
				{
					Name:    "library_crate",
					Version: "0.1.0",
				},
			},
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

			got, _, err := binary.NewParser().Parse(f)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
