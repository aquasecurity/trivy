package rubygems_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/rubygems"
)

func TestRubyGemsComparer_IsVulnerable(t *testing.T) {
	type args struct {
		currentVersion string
		advisory       types.Advisory
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "happy path",
			args: args{
				currentVersion: "1.2.3",
				advisory: types.Advisory{
					PatchedVersions: []string{">=1.2.0"},
				},
			},
			want: false,
		},
		{
			name: "pre-release",
			args: args{
				currentVersion: "1.2.3.a",
				advisory: types.Advisory{
					PatchedVersions: []string{">=1.2.3"},
				},
			},
			want: true,
		},
		{
			name: "pre-release without dot",
			args: args{
				currentVersion: "4.1a",
				advisory: types.Advisory{
					UnaffectedVersions: []string{"< 4.2b1"},
				},
			},
			want: false,
		},
		{
			// https://github.com/aquasecurity/trivy/issues/108
			name: "hyphen",
			args: args{
				currentVersion: "1.9.25-x86-mingw32",
				advisory: types.Advisory{
					PatchedVersions: []string{">=1.9.24"},
				},
			},
			want: false,
		},
		{
			// https://github.com/aquasecurity/trivy/issues/108
			name: "pessimistic",
			args: args{
				currentVersion: "1.8.6-java",
				advisory: types.Advisory{
					PatchedVersions: []string{"~> 1.5.5", "~> 1.6.8", ">= 1.7.7"},
				},
			},
			want: false,
		},
		{
			name: "invalid version",
			args: args{
				currentVersion: "1.2..4",
				advisory: types.Advisory{
					PatchedVersions: []string{">=1.2.3"},
				},
			},
			want: false,
		},
		{
			name: "invalid constraint",
			args: args{
				currentVersion: "1.2.4",
				advisory: types.Advisory{
					PatchedVersions: []string{"!1.2.0"},
				},
			},
			want: false,
		},
		{
			name: "space-separated OR ranges (trivy-db format)",
			args: args{
				currentVersion: "1.5.0",
				advisory: types.Advisory{
					VulnerableVersions: []string{">=1.0.0, <2.0.0 >=2.0.0, <3.0.0"},
					PatchedVersions:    []string{">=3.0.0"},
				},
			},
			want: true,
		},
		{
			name: "space-separated OR ranges - not vulnerable (patched version)",
			args: args{
				currentVersion: "3.0.0",
				advisory: types.Advisory{
					VulnerableVersions: []string{">=1.0.0, <2.0.0 >=2.0.0, <3.0.0"},
					PatchedVersions:    []string{">=3.0.0"},
				},
			},
			want: false,
		},
		{
			name: "space-separated OR ranges - matches second range",
			args: args{
				currentVersion: "2.5.0",
				advisory: types.Advisory{
					VulnerableVersions: []string{">=1.0.0, <2.0.0 >=2.0.0, <3.0.0"},
					PatchedVersions:    []string{">=2.0.0 <2.0.0", ">=3.0.0"},
				},
			},
			want: true,
		},
		{
			name: "complex space-separated OR ranges with pre-release versions",
			args: args{
				currentVersion: "2.1.0.beta.5",
				advisory: types.Advisory{
					VulnerableVersions: []string{">=1.0.0.alpha.1, <2.0.0 >=2.0.0.beta.1, <2.1.0 >=2.1.0.rc.1, <2.2.0"},
					PatchedVersions:    []string{">=2.0.0, <2.0.0.beta.1", ">=2.1.0, <2.1.0.rc.1", ">=2.2.0"},
				},
			},
			want: true,
		},
		{
			name: "complex space-separated OR ranges - matches third range with rc",
			args: args{
				currentVersion: "2.1.5.rc.3",
				advisory: types.Advisory{
					VulnerableVersions: []string{">=1.0.0.alpha.1, <2.0.0 >=2.0.0.beta.1, <2.1.0 >=2.1.0.rc.1, <2.2.0"},
					PatchedVersions:    []string{">=2.0.0, <2.0.0.beta.1", ">=2.1.0, <2.1.0.rc.1", ">=2.2.0"},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := rubygems.Comparer{}
			got := r.IsVulnerable(tt.args.currentVersion, tt.args.advisory)
			assert.Equal(t, tt.want, got)
		})
	}
}
