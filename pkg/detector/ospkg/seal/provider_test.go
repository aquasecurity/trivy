package seal_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/detector/ospkg/seal"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestProvider(t *testing.T) {
	tests := []struct {
		name     string
		osFamily ftypes.OSType
		pkgs     []ftypes.Package
		want     bool // true if driver should be returned, false if nil
	}{
		{
			name:     "returns driver when package name starts with seal",
			osFamily: ftypes.Debian,
			pkgs: []ftypes.Package{
				{Name: "seal-agent", Version: "1.0.0"},
				{Name: "bash", Version: "5.1"},
			},
			want: true,
		},
		{
			name:     "returns driver when src name starts with seal",
			osFamily: ftypes.Ubuntu,
			pkgs: []ftypes.Package{
				{Name: "libssl", SrcName: "seal-ssl", Version: "1.2.3"},
				{Name: "curl", Version: "7.81.0"},
			},
			want: true,
		},
		{
			name:     "returns nil when no seal packages present",
			osFamily: ftypes.Alpine,
			pkgs: []ftypes.Package{
				{Name: "musl", Version: "1.2.3"},
				{Name: "busybox", Version: "1.36.1"},
			},
			want: false,
		},
		{
			name:     "returns nil for empty package list",
			osFamily: ftypes.Debian,
			pkgs:     []ftypes.Package{},
			want:     false,
		},
		{
			name:     "case-insensitive: Seal prefix matched",
			osFamily: ftypes.Ubuntu,
			pkgs: []ftypes.Package{
				{Name: "Seal-agent", Version: "2.0.0"},
			},
			want: true,
		},
		{
			name:     "returns nil for unsupported OS family even with seal package",
			osFamily: ftypes.Fedora,
			pkgs: []ftypes.Package{
				{Name: "seal-agent", Version: "1.0.0"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := seal.Provider(tt.osFamily, tt.pkgs)
			if tt.want {
				require.NotNil(t, d, "expected a non-nil driver when seal package is present")
			} else {
				assert.Nil(t, d, "expected nil driver when no seal package is present")
			}
		})
	}
}
