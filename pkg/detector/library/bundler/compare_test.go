package bundler_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/bundler"
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bundler.RubyGemsComparer{}
			got := r.IsVulnerable(tt.args.currentVersion, tt.args.advisory)
			assert.Equal(t, tt.want, got)
		})
	}
}
