package pylock_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/pylock"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		wantPkgs []ftypes.Package
		wantDeps []ftypes.Dependency
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name: "happy path",
			file: "testdata/pylock.toml",
			wantPkgs: []ftypes.Package{
				{
					ID:      "attrs@25.4.0",
					Name:    "attrs",
					Version: "25.4.0",
				},
				{
					ID:      "certifi@2025.10.5",
					Name:    "certifi",
					Version: "2025.10.5",
				},
				{
					ID:      "charset-normalizer@3.4.3",
					Name:    "charset-normalizer",
					Version: "3.4.3",
				},
				{
					ID:      "ham@3.0.0",
					Name:    "ham",
					Version: "3.0.0",
				},
				{
					ID:      "idna@3.10",
					Name:    "idna",
					Version: "3.10",
				},
				{
					ID:      "requests@2.32.5",
					Name:    "requests",
					Version: "2.32.5",
				},
				{
					ID:      "spam@1.0.0",
					Name:    "spam",
					Version: "1.0.0",
				},
				{
					ID:      "spam@1.1.0",
					Name:    "spam",
					Version: "1.1.0",
				},
				{
					ID:      "urllib3@2.5.0",
					Name:    "urllib3",
					Version: "2.5.0",
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID:        "ham@3.0.0",
					DependsOn: []string{"spam@1.1.0"},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:    "sad path",
			file:    "testdata/sad.toml",
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)
			defer f.Close()

			p := pylock.NewParser()
			gotPkgs, gotDeps, err := p.Parse(t.Context(), f)
			if !tt.wantErr(t, err, fmt.Sprintf("Parse(%v)", tt.file)) {
				return
			}
			assert.Equalf(t, tt.wantPkgs, gotPkgs, "Parse(%v)", tt.file)
			assert.Equalf(t, tt.wantDeps, gotDeps, "Parse(%v)", tt.file)
		})
	}
}
