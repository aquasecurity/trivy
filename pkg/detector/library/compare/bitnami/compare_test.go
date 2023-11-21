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
			name: "vulnerable",
			args: args{
				currentVersion: "1.2.3",
				advisory: types.Advisory{
					PatchedVersions: []string{">=1.2.4"},
				},
			},
			want: true,
		},
		{
			name: "patched with revision on current version",
			args: args{
				currentVersion: "1.2.3-r1",
				advisory: types.Advisory{
					PatchedVersions: []string{">=1.2.3"},
				},
			},
			want: false,
		},
		{
			name: "vulnerable with revision on current version",
			args: args{
				currentVersion: "1.2.3-r1",
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
					PatchedVersions: []string{">=1.2.3-r1"},
				},
			},
			want: false,
		},
		{
			name: "vulnerable with revision on patch",
			args: args{
				currentVersion: "1.2.3",
				advisory: types.Advisory{
					PatchedVersions: []string{">=1.2.3-r1"},
				},
			},
			want: true,
		},
		{
			name: "patched with revisions on both current and patch",
			args: args{
				currentVersion: "1.2.4-r2",
				advisory: types.Advisory{
					PatchedVersions: []string{">=1.2.3-r1"},
				},
			},
			want: false,
		},
		{
			name: "vulnerable with revision on both current and patch",
			args: args{
				currentVersion: "1.2.3-r0",
				advisory: types.Advisory{
					PatchedVersions: []string{">=1.2.3-r1"},
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
