package bitnami_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/bitnami"
)

func TestBitnamiComparer_IsVulnerable(t *testing.T) {
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
			name: "not vulnerable",
			args: args{
				currentVersion: "1.2.3",
				advisory: types.Advisory{
					VulnerableVersions: []string{"<1.2.3"},
				},
			},
			want: false,
		},
		{
			name: "vulnerable",
			args: args{
				currentVersion: "1.2.3",
				advisory: types.Advisory{
					VulnerableVersions: []string{"<=1.2.3"},
				},
			},
			want: true,
		},
		{
			name: "patched",
			args: args{
				currentVersion: "1.2.3",
				advisory: types.Advisory{
					PatchedVersions: []string{">=1.2.3"},
				},
			},
			want: false,
		},
		{
			name: "unaffected",
			args: args{
				currentVersion: "1.2.3",
				advisory: types.Advisory{
					UnaffectedVersions: []string{"=1.2.3"},
				},
			},
			want: false,
		},
		{
			name: "vulnerable based on patched & unaffected versions",
			args: args{
				currentVersion: "1.2.3",
				advisory: types.Advisory{
					UnaffectedVersions: []string{"=1.2.0"},
					PatchedVersions:    []string{">=1.2.4"},
				},
			},
			want: true,
		},
		{
			name: "patched with revision on current version",
			args: args{
				currentVersion: "1.2.3-1",
				advisory: types.Advisory{
					PatchedVersions: []string{">=1.2.3"},
				},
			},
			want: false,
		},
		{
			name: "vulnerable with revision on current version",
			args: args{
				currentVersion: "1.2.3-1",
				advisory: types.Advisory{
					PatchedVersions: []string{">=1.2.4"},
				},
			},
			want: true,
		},
		{
			name: "patched with revision on patch",
			args: args{
				currentVersion: "1.2.4",
				advisory: types.Advisory{
					PatchedVersions: []string{">=1.2.3-1"},
				},
			},
			want: false,
		},
		{
			name: "vulnerable with revision on patch",
			args: args{
				currentVersion: "1.2.3",
				advisory: types.Advisory{
					PatchedVersions: []string{">=1.2.3-1"},
				},
			},
			want: true,
		},
		{
			name: "patched with revisions on both current and patch",
			args: args{
				currentVersion: "1.2.4-2",
				advisory: types.Advisory{
					PatchedVersions: []string{">=1.2.3-1"},
				},
			},
			want: false,
		},
		{
			name: "vulnerable with revision on both current and patch",
			args: args{
				currentVersion: "1.2.3-0",
				advisory: types.Advisory{
					PatchedVersions: []string{">=1.2.3-1"},
				},
			},
			want: true,
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
			name: "complex space-separated OR ranges with revision versions",
			args: args{
				currentVersion: "2.1.0-2",
				advisory: types.Advisory{
					VulnerableVersions: []string{">=1.0.0-1, <2.0.0 >=2.0.0-1, <2.1.0 >=2.1.0-1, <2.2.0"},
					PatchedVersions:    []string{">=2.0.0, <2.0.0-1", ">=2.1.0, <2.1.0-1", ">=2.2.0"},
				},
			},
			want: true,
		},
		{
			name: "complex space-separated OR ranges - matches third range with revision",
			args: args{
				currentVersion: "2.1.5-3",
				advisory: types.Advisory{
					VulnerableVersions: []string{">=1.0.0-1, <2.0.0 >=2.0.0-1, <2.1.0 >=2.1.0-1, <2.2.0"},
					PatchedVersions:    []string{">=2.0.0, <2.0.0-1", ">=2.1.0, <2.1.0-1", ">=2.2.0"},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := bitnami.Comparer{}
			got := b.IsVulnerable(tt.args.currentVersion, tt.args.advisory)
			assert.Equal(t, tt.want, got)
		})
	}
}
