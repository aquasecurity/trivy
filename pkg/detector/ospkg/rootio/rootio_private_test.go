package rootio

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestScanner_IsVulnerable(t *testing.T) {
	tests := []struct {
		name             string
		installedVersion string
		vulnerableRanges []string
		want             bool
	}{
		{
			name:             "Installed vulnerable vendor version. There is no fix",
			installedVersion: "1.0.0",
			vulnerableRanges: []string{},
			want:             true,
		},
		{
			name:             "Installed vulnerable vendor version, fix by vendor",
			installedVersion: "1.0.0",
			vulnerableRanges: []string{
				"<1.0.0-2",
			},
			want: true,
		},
		{
			name:             "Installed non-vulnerable vendor version, fix by vendor",
			installedVersion: "1.0.0-2",
			vulnerableRanges: []string{
				"<1.0.0-2",
			},
			want: false,
		},
		{
			name:             "Installed vulnerable vendor version, fix by root.io (root.io version)",
			installedVersion: "1.0.0-2",
			vulnerableRanges: []string{
				"<1.0.0-2.root.io",
			},
			want: true,
		},
		{
			name:             "Installed non-vulnerable vendor version, fix by root.io (root.io version)",
			installedVersion: "1.0.0-3",
			vulnerableRanges: []string{
				"<1.0.0-2.root.io",
			},
			want: false,
		},
		{
			name:             "Installed vulnerable vendor version, fix by root.io (root.io + vendor versions)",
			installedVersion: "1.0.0-2",
			vulnerableRanges: []string{
				"<1.0.0-2.root.io",
				">=1.0.0-2 <1.0.0-3",
			},
			want: true,
		},
		{
			name:             "Installed non-vulnerable vendor version, fix by root.io (root.io + vendor versions)",
			installedVersion: "1.0.0-3",
			vulnerableRanges: []string{
				"<1.0.0-2.root.io",
				">=1.0.0-2 <1.0.0-3",
			},
			want: false,
		},
		{
			name:             "Installed vulnerable root.io version, fix by root.io",
			installedVersion: "1.0.0-1.root.io",
			vulnerableRanges: []string{
				"<1.0.0-2.root.io",
			},
			want: true,
		},
		{
			name:             "Installed non-vulnerable root.io version, fix by root.io",
			installedVersion: "1.0.0-2.root.io",
			vulnerableRanges: []string{
				"<1.0.0-2.root.io",
			},
			want: false,
		},
		{
			name:             "Installed vulnerable root.io version, fix by vendor",
			installedVersion: "1.0.0-1.root.io",
			vulnerableRanges: []string{
				"<1.0.0-2",
			},
			want: true,
		},
		{
			name:             "Installed non-vulnerable root.io version, fix by vendor",
			installedVersion: "1.0.0-2.root.io",
			vulnerableRanges: []string{
				"<1.0.0-1",
			},
			want: false,
		},
		{
			name:             "Installed vulnerable root.io version, fix by root.io (root.io + vendor versions)",
			installedVersion: "1.0.0-1.root.io",
			vulnerableRanges: []string{
				"<1.0.0-2.root.io",
				">=1.0.0-2 <1.0.0-2",
			},
			want: true,
		},
		{
			name:             "Installed non-vulnerable root.io version, fix by root.io (root.io + vendor versions)",
			installedVersion: "1.0.0-2.root.io",
			vulnerableRanges: []string{
				"<1.0.0-2.root.io",
				">=1.0.0-2 <1.0.0-2",
			},
			want: false,
		},
		{
			name:             "Installed non-vulnerable root.io version, fix by root.io (root.io + root.io + vendor versions)",
			installedVersion: "1.0.0-2.root.io",
			vulnerableRanges: []string{
				"<1.0.0-2.root.io",
				">1.0.0-2.root.io <1.0.0-2",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewScanner(ftypes.Debian)
			vulnerable := scanner.isVulnerable(t.Context(), tt.installedVersion, types.Advisory{VulnerableVersions: tt.vulnerableRanges})
			require.Equal(t, tt.want, vulnerable)
		})
	}
}
