package maven_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/maven"
)

func TestComparer_IsVulnerable(t *testing.T) {
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
			name: "final release",
			args: args{
				currentVersion: "1.2.3.final",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"<1.2.3"},
					PatchedVersions:    []string{"1.2.3"},
				},
			},
			want: false,
		},
		{
			name: "pre-release",
			args: args{
				currentVersion: "1.2.3-a1",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"<1.2.3"},
					PatchedVersions:    []string{">=1.2.3"},
				},
			},
			want: true,
		},
		{
			name: "multiple constraints",
			args: args{
				currentVersion: "2.0.0",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{">=1.7.0 <1.7.16", ">=1.8.0 <1.8.8", ">=2.0.0 <2.0.8", ">=3.0.0-beta.1 <3.0.0-beta.7"},
					PatchedVersions:    []string{">=3.0.0-beta.7", ">=2.0.8 <3.0.0-beta.1", ">=1.8.8 <2.0.0", ">=1.7.16 <1.8.0"},
				},
			},
			want: true,
		},
		{
			name: "version requirements",
			args: args{
				currentVersion: "1.2.3",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"(,1.2.3]"},
					PatchedVersions:    []string{"1.2.4"},
				},
			},
			want: true,
		},
		{
			name: "version soft requirements happy",
			args: args{
				currentVersion: "1.2.3",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"1.2.3"},
					PatchedVersions:    []string{"1.2.4"},
				},
			},
			want: true,
		},
		{
			name: "version soft requirements",
			args: args{
				currentVersion: "1.2.3",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"1.2.2"},
					PatchedVersions:    []string{"1.2.4"},
				},
			},
			want: false,
		},
		{
			name: "invalid constraint",
			args: args{
				currentVersion: "1.2.3",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{`<1.0\.0`},
				},
			},
			want: false,
		},
		{
			name: "version with fork suffix not vulnerable",
			args: args{
				currentVersion: "10.14.3.0-magnolia",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{">=10.1.1.0 <10.14.3", ">=10.15.0.0 <10.15.2.1", ">=10.16.0.0 <10.16.1.2", ">=10.17.0.s0 <10.17.1.0"},
					PatchedVersions:    []string{"10.14.3", "10.15.2.1", "10.16.1.2", "10.17.1.0"},
				},
			},
			want: false,
		},
		{
			name: "version with fork suffix vulnerable",
			args: args{
				currentVersion: "10.14.2.0-magnolia",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{">=10.1.1.0 <10.14.3", ">=10.15.0.0 <10.15.2.1", ">=10.16.0.0 <10.16.1.2", ">=10.17.0.s0 <10.17.1.0"},
					PatchedVersions:    []string{"10.14.3", "10.15.2.1", "10.16.1.2", "10.17.1.0"},
				},
			},
			want: true,
		},
		{
			name: "space-separated OR ranges (trivy-db format)",
			args: args{
				currentVersion: "2.0.0",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{">=1.7.0 <1.7.16 >=1.8.0 <1.8.8 >=2.0.0 <2.0.8"},
					PatchedVersions:    []string{">=1.7.16 <1.8.0", ">=1.8.8 <2.0.0", ">=2.0.8"},
				},
			},
			want: true,
		},
		{
			name: "space-separated OR ranges - not vulnerable (patched version)",
			args: args{
				currentVersion: "2.0.8",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{">=1.7.0 <1.7.16 >=1.8.0 <1.8.8 >=2.0.0 <2.0.8"},
					PatchedVersions:    []string{">=1.7.16 <1.8.0", ">=1.8.8 <2.0.0", ">=2.0.8"},
				},
			},
			want: false,
		},
		{
			name: "complex space-separated OR ranges with milestone versions (.M)",
			args: args{
				currentVersion: "9.0.0.M2",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{">=9.0.0.M1 <9.0.5 >=9.0.5.M1 <9.0.37 >=9.1.0.M1 <9.1.0"},
					PatchedVersions:    []string{">=9.0.5, <9.0.5.M1", ">=9.0.37, <9.1.0.M1", ">=9.1.0"},
				},
			},
			want: true,
		},
		{
			name: "complex space-separated OR ranges - matches second range with milestone",
			args: args{
				currentVersion: "9.0.10.M5",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{">=9.0.0.M1 <9.0.5 >=9.0.5.M1 <9.0.37 >=9.1.0.M1 <9.1.0"},
					PatchedVersions:    []string{">=9.0.5, <9.0.5.M1", ">=9.0.37, <9.1.0.M1", ">=9.1.0"},
				},
			},
			want: true,
		},
		{
			name: "complex space-separated OR ranges with alpha/beta/rc versions",
			args: args{
				currentVersion: "2.1.0-beta-5",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{">=1.0.0-alpha-1 <2.0.0 >=2.0.0-beta-1 <2.1.0 >=2.1.0-rc-1 <2.2.0"},
					PatchedVersions:    []string{">=2.0.0, <2.0.0-beta-1", ">=2.1.0, <2.1.0-rc-1", ">=2.2.0"},
				},
			},
			want: true,
		},
		{
			name: "comma-separated AND constraint should not be split (regression test)",
			args: args{
				currentVersion: "2.13.1",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{">= 2.0.0, <= 2.9.10.3"},
					PatchedVersions:    []string{">= 2.9.10.4"},
				},
			},
			want: false,
		},
		{
			name: "comma-separated AND constraint - actually vulnerable",
			args: args{
				currentVersion: "2.9.10.2",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{">= 2.0.0, <= 2.9.10.3"},
					PatchedVersions:    []string{">= 2.9.10.4"},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := maven.Comparer{}
			got := c.IsVulnerable(tt.args.currentVersion, tt.args.advisory)
			assert.Equal(t, tt.want, got)
		})
	}
}
