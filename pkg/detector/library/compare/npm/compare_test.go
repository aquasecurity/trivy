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
		name              string
		withBuildMetadata bool
		args              args
		want              bool
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
			// Without WithBuildMetadata, build metadata is ignored,
			// so ">= 1.2.3+build.1, < 1.2.3+build.2" turns into ">= 1.2.3, < 1.2.3" and matches nothing.
			name:              "without WithBuildMetadata: build metadata ignored",
			withBuildMetadata: false,
			args: args{
				currentVersion: "1.2.3+build.1",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{">=1.2.3+build.1, <1.2.3+build.2"},
					PatchedVersions:    []string{"1.2.3+build.2"},
				},
			},
			want: false,
		},
		{
			name:              "without WithBuildMetadata: metadata-only versions remain equal",
			withBuildMetadata: false,
			args: args{
				currentVersion: "1.2.3+build.2",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"1.2.3+build.1"},
				},
			},
			want: true,
		},
		{
			name:              "with WithBuildMetadata: release is below first Echo build",
			withBuildMetadata: true,
			args: args{
				currentVersion: "1.2.3",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"<1.2.3+echo.1"},
					PatchedVersions:    []string{"1.2.3+echo.1"},
				},
			},
			want: true,
		},
		{
			name:              "with WithBuildMetadata: Echo patched version does not suppress release",
			withBuildMetadata: true,
			args: args{
				currentVersion: "1.2.3",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"<1.2.4"},
					PatchedVersions:    []string{"1.2.3+echo.1"},
				},
			},
			want: true,
		},
		{
			name:              "with WithBuildMetadata: exact Echo patched version is suppressed",
			withBuildMetadata: true,
			args: args{
				currentVersion: "1.2.3+echo.1",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"<1.2.4"},
					PatchedVersions:    []string{"1.2.3+echo.1"},
				},
			},
			want: false,
		},
		{
			name:              "with WithBuildMetadata: later Echo build is above first Echo build",
			withBuildMetadata: true,
			args: args{
				currentVersion: "1.2.3+echo.2",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"<1.2.3+echo.1"},
					PatchedVersions:    []string{"1.2.3+echo.1"},
				},
			},
			want: false,
		},
		{
			name:              "with WithBuildMetadata: build below the patched build",
			withBuildMetadata: true,
			args: args{
				currentVersion: "1.2.3+build.1",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{">=1.2.3+build.1, <1.2.3+build.2"},
					PatchedVersions:    []string{"1.2.3+build.2"},
				},
			},
			want: true,
		},
		{
			name:              "with WithBuildMetadata: patched build",
			withBuildMetadata: true,
			args: args{
				currentVersion: "1.2.3+build.2",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{">=1.2.3+build.1, <1.2.3+build.2"},
					PatchedVersions:    []string{"1.2.3+build.2"},
				},
			},
			want: false,
		},
		{
			// Numeric identifiers are compared numerically, so build.10 > build.2.
			name:              "with WithBuildMetadata: build above the patched build",
			withBuildMetadata: true,
			args: args{
				currentVersion: "1.2.3+build.10",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{">=1.2.3+build.1, <1.2.3+build.2"},
					PatchedVersions:    []string{"1.2.3+build.2"},
				},
			},
			want: false,
		},
		{
			name:              "with WithBuildMetadata: build of an older release",
			withBuildMetadata: true,
			args: args{
				currentVersion: "1.2.2+build.5",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"<1.2.3+build.1"},
					PatchedVersions:    []string{"1.2.3+build.1"},
				},
			},
			want: true,
		},
		{
			name:              "with WithBuildMetadata: build of a newer release",
			withBuildMetadata: true,
			args: args{
				currentVersion: "1.2.4+build.1",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"<1.2.3+build.1"},
					PatchedVersions:    []string{"1.2.3+build.1"},
				},
			},
			want: false,
		},
		{
			name:              "with WithBuildMetadata: build of a pre-release below the patched build",
			withBuildMetadata: true,
			args: args{
				currentVersion: "19.0.0-next.3+build.1",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"<19.0.0-next.3+build.2"},
					PatchedVersions:    []string{"19.0.0-next.3+build.2"},
				},
			},
			want: true,
		},
		{
			name:              "with WithBuildMetadata: build of a pre-release equal to the patched build",
			withBuildMetadata: true,
			args: args{
				currentVersion: "19.0.0-next.3+build.2",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"<19.0.0-next.3+build.2"},
					PatchedVersions:    []string{"19.0.0-next.3+build.2"},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c npm.Comparer
			if tt.withBuildMetadata {
				c = npm.NewComparer(npm.WithBuildMetadata())
			}
			got := c.IsVulnerable(tt.args.currentVersion, tt.args.advisory)
			assert.Equal(t, tt.want, got)
		})
	}
}
