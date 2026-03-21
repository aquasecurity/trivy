package bottlerocket_inventory

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

var pkgs = []types.Package{
	{
		ID:      "glibc@1:2.40-1.1740525475.e3a5862c.br1",
		Name:    "glibc",
		Version: "2.40",
		Release: "1.1740525475.e3a5862c.br1",
		Epoch:   1,
		Arch:    "x86_64",
	},
	{
		ID:      "kernel-6.1@6.1.128-1.1740603423.4d405dc9.br1",
		Name:    "kernel-6.1",
		Version: "6.1.128",
		Release: "1.1740603423.4d405dc9.br1",
		Epoch:   0,
		Arch:    "x86_64",
	},
	{
		ID:      "systemd@252.22-1.1740525475.e3a5862c.br1",
		Name:    "systemd",
		Version: "252.22",
		Release: "1.1740525475.e3a5862c.br1",
		Epoch:   0,
		Arch:    "x86_64",
	},
}

func TestParseApplicationInventory(t *testing.T) {
	var tests = []struct {
		name     string
		path     string
		wantPkgs []types.Package
	}{
		{
			name:     "happy path",
			path:     "./testdata/application-inventory.json",
			wantPkgs: pkgs,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := bottlerocketInventoryAnalyzer{}
			f, err := os.Open(tt.path)
			require.NoError(t, err)
			defer f.Close()
			gotPkgs, err := a.parseApplicationInventory(t.Context(), f)
			require.NoError(t, err)

			assert.Equal(t, tt.wantPkgs, gotPkgs)
		})
	}
}
