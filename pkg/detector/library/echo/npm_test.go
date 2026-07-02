package echo

import (
	"testing"

	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
)

func TestNpmComparer_IsVulnerable(t *testing.T) {
	tests := []struct {
		name     string
		ver      string
		advisory dbTypes.Advisory
		want     bool
	}{
		{
			name: "installed echo build below the fixed echo build",
			ver:  "7.23.2+echo.1",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{">=7.23.2+echo.1, <7.23.2+echo.2"},
				PatchedVersions:    []string{"7.23.2+echo.2"},
			},
			want: true,
		},
		{
			name: "installed echo build equals the fixed echo build",
			ver:  "7.23.2+echo.2",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{">=7.23.2+echo.1, <7.23.2+echo.2"},
				PatchedVersions:    []string{"7.23.2+echo.2"},
			},
			want: false,
		},
		{
			name: "installed echo build above the fixed echo build",
			ver:  "7.23.2+echo.10",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{">=7.23.2+echo.1, <7.23.2+echo.2"},
				PatchedVersions:    []string{"7.23.2+echo.2"},
			},
			want: false,
		},
		{
			name: "echo build of an older base version",
			ver:  "7.23.1+echo.5",
			advisory: dbTypes.Advisory{
				// {"introduced": "0"} ranges drop the ">=0" comparator.
				VulnerableVersions: []string{"<7.23.2+echo.1"},
				PatchedVersions:    []string{"7.23.2+echo.1"},
			},
			want: true,
		},
		{
			name: "echo build of a newer base version",
			ver:  "7.23.3+echo.1",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"<7.23.2+echo.1"},
				PatchedVersions:    []string{"7.23.2+echo.1"},
			},
			want: false,
		},
		{
			name: "spaces between operator and version",
			ver:  "3.1.8+echo.1",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{">= 3.1.8+echo.1, < 3.1.8+echo.999"},
				PatchedVersions:    []string{"3.1.8+echo.999"},
			},
			want: true,
		},
		{
			name: "multiple vulnerable ranges (OR)",
			ver:  "2.0.0+echo.1",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"<1.0.0+echo.9", ">=2.0.0, <2.0.0+echo.2"},
				PatchedVersions:    []string{"1.0.0+echo.9", "2.0.0+echo.2"},
			},
			want: true,
		},
		{
			name: "echo build of a prerelease below the fixed prerelease build",
			ver:  "19.0.0-next.3+echo.1",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"<19.0.0-next.3+echo.2"},
				PatchedVersions:    []string{"19.0.0-next.3+echo.2"},
			},
			want: true,
		},
		{
			name: "echo build of a prerelease equals the fixed prerelease build",
			ver:  "19.0.0-next.3+echo.2",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"<19.0.0-next.3+echo.2"},
				PatchedVersions:    []string{"19.0.0-next.3+echo.2"},
			},
			want: false,
		},
		{
			name: "exact match without operator",
			ver:  "1.2.3+echo.1",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"1.2.3+echo.1"},
			},
			want: true,
		},
		{
			name: "unparseable installed version is not vulnerable",
			ver:  "not-a-version",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"<1.0.0+echo.1"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := npmComparer{}.IsVulnerable(tt.ver, tt.advisory)
			require.Equal(t, tt.want, got)
		})
	}
}
