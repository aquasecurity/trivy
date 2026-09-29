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
		ID:      "glibc@1:2.43-1.1781747852.5f13b929.br1",
		Name:    "glibc",
		Version: "2.43",
		Release: "1.1781747852.5f13b929.br1",
		Epoch:   1,
		Arch:    "x86_64",
	},
	{
		ID:      "kernel-6.1@6.1.172-1.1779997967.64782dc8.br1",
		Name:    "kernel-6.1",
		Version: "6.1.172",
		Release: "1.1779997967.64782dc8.br1",
		Epoch:   0,
		Arch:    "x86_64",
	},
	{
		ID:      "runc@1:1.3.5-1.1781747852.5f13b929.br1",
		Name:    "runc",
		Version: "1.3.5",
		Release: "1.1781747852.5f13b929.br1",
		Epoch:   1,
		Arch:    "x86_64",
	},
	{
		ID:      "coreutils@9.10-1.1781747852.5f13b929.br1",
		Name:    "coreutils",
		Version: "9.10",
		Release: "1.1781747852.5f13b929.br1",
		Epoch:   0,
		Arch:    "x86_64",
	},
	{
		ID:      "grub@1:2.06-1.1779997967.64782dc8.br1",
		Name:    "grub",
		Version: "2.06",
		Release: "1.1779997967.64782dc8.br1",
		Epoch:   1,
		Arch:    "x86_64",
	},
}

// pkgsNoEpoch is the expected result for an inventory without an Epoch field
// (older Bottlerocket releases), where the epoch defaults to 0.
var pkgsNoEpoch = []types.Package{
	{
		ID:      "acpid@1.19.2-29cc92cc",
		Name:    "acpid",
		Version: "1.19.2",
		Release: "29cc92cc",
		Epoch:   0,
		Arch:    "x86_64",
	},
	{
		ID:      "systemd@1.19.2-29cc92cc",
		Name:    "systemd",
		Version: "1.19.2",
		Release: "29cc92cc",
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
		{
			name:     "without epoch",
			path:     "./testdata/application-inventory-no-epoch.json",
			wantPkgs: pkgsNoEpoch,
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
