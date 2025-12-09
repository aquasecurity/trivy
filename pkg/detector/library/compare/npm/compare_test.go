package npm_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/npm"
)

func TestNpmComparer_IsVulnerable(t *testing.T) {
	type args struct {
		currentVersion string
		advisory       dbTypes.Advisory
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "happy path",
			args: args{
				currentVersion: "1.0.0",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"<=1.0"},
					PatchedVersions:    []string{">=1.1"},
				},
			},
			want: true,
		},
		{
			name: "prerelease",
			args: args{
				currentVersion: "1.45.1-lts.1",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{">=1.4.4-lts.1, <2.0.0"},
					PatchedVersions:    []string{"2.0.0"},
				},
			},
			want: true,
		},
		{
			name: "no patch",
			args: args{
				currentVersion: "1.2.3",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"<=99.999.99999"},
					PatchedVersions:    []string{"<0.0.0"},
				},
			},
			want: true,
		},
		{
			name: "no patch with wildcard",
			args: args{
				currentVersion: "1.2.3",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"*"},
					PatchedVersions:    nil,
				},
			},
			want: true,
		},
		{
			name: "pre-release",
			args: args{
				currentVersion: "1.2.3-alpha",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"<=1.2.2"},
					PatchedVersions:    []string{">=1.2.2"},
				},
			},
			want: false,
		},
		{
			name: "multiple constraints",
			args: args{
				currentVersion: "2.0.0",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{
						">=1.7.0 <1.7.16", ">=1.8.0 <1.8.8", ">=2.0.0 <2.0.8", ">=3.0.0-beta.1 <3.0.0-beta.7",
					},
					PatchedVersions: []string{
						">=3.0.0-beta.7", ">=2.0.8 <3.0.0-beta.1", ">=1.8.8 <2.0.0", ">=1.7.16 <1.8.0",
					},
				},
			},
			want: true,
		},
		{
			name: "x",
			args: args{
				currentVersion: "2.0.1",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"2.0.x", "2.1.x"},
					PatchedVersions:    []string{">=2.2.x"},
				},
			},
			want: true,
		},
		{
			name: "exact versions",
			args: args{
				currentVersion: "2.1.0-M1",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"2.1.0-M1", "2.1.0-M2"},
					PatchedVersions:    []string{">=2.1.0"},
				},
			},
			want: true,
		},
		{
			name: "caret",
			args: args{
				currentVersion: "2.0.18",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"<2.0.18", "<3.0.16"},
					PatchedVersions:    []string{"^2.0.18", "^3.0.16"},
				},
			},
			want: false,
		},
		{
			name: "invalid version",
			args: args{
				currentVersion: "1.2..4",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"<1.0.0"},
				},
			},
			want: false,
		},
		{
			name: "invalid constraint",
			args: args{
				currentVersion: "1.2.4",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"!1.0.0"},
				},
			},
			want: false,
		},
		{
			name: "space-separated OR ranges (trivy-db format)",
			args: args{
				currentVersion: "15.0.4-canary.30",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{">=14.3.0-canary.77, <15.0.5 >=15.1.0-canary.0, <15.1.9"},
					PatchedVersions:    []string{">=15.0.5 <15.1.0-canary.0", ">=15.1.9"},
				},
			},
			want: true,
		},
		{
			name: "space-separated OR ranges - not vulnerable (patched version)",
			args: args{
				currentVersion: "15.0.5",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{">=14.3.0-canary.77, <15.0.5 >=15.1.0-canary.0, <15.1.9"},
					PatchedVersions:    []string{">=15.0.5 <15.1.0-canary.0", ">=15.1.9"},
				},
			},
			want: false,
		},
		{
			name: "space-separated OR ranges - matches second range",
			args: args{
				currentVersion: "15.1.5-canary.10",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{">=14.3.0-canary.77, <15.0.5 >=15.1.0-canary.0, <15.1.9"},
					PatchedVersions:    []string{">=15.0.5 <15.1.0-canary.0", ">=15.1.9"},
				},
			},
			want: true,
		},
		{
			name: "complex space-separated OR ranges with multiple pre-release formats",
			args: args{
				currentVersion: "2.1.0-beta.5",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{">=1.0.0-alpha.1, <2.0.0 >=2.0.0-beta.1, <2.1.0 >=2.1.0-rc.1, <2.2.0"},
					PatchedVersions:    []string{">=2.0.0, <2.0.0-beta.1", ">=2.1.0, <2.1.0-rc.1", ">=2.2.0"},
				},
			},
			want: true,
		},
		{
			name: "complex space-separated OR ranges - matches third range with rc",
			args: args{
				currentVersion: "2.1.5-rc.3",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{">=1.0.0-alpha.1, <2.0.0 >=2.0.0-beta.1, <2.1.0 >=2.1.0-rc.1, <2.2.0"},
					PatchedVersions:    []string{">=2.0.0, <2.0.0-beta.1", ">=2.1.0, <2.1.0-rc.1", ">=2.2.0"},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := npm.Comparer{}
			got := c.IsVulnerable(tt.args.currentVersion, tt.args.advisory)
			assert.Equal(t, tt.want, got)
		})
	}
}
