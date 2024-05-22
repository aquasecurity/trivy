package compare_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
)

func TestGenericComparer_IsVulnerable(t *testing.T) {
	type args struct {
		ver      string
		advisory types.Advisory
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "happy path",
			args: args{
				ver: "1.2.3",
				advisory: types.Advisory{
					VulnerableVersions: []string{"<=1.0"},
					PatchedVersions:    []string{">=1.1"},
				},
			},
		},
		{
			name: "no patch",
			args: args{
				ver: "1.2.3",
				advisory: types.Advisory{
					VulnerableVersions: []string{"<=99.999.99999"},
					PatchedVersions:    []string{"<0.0.0"},
				},
			},
			want: true,
		},
		{
			name: "pre-release",
			args: args{
				ver: "1.2.2-alpha",
				advisory: types.Advisory{
					VulnerableVersions: []string{"<=1.2.2"},
					PatchedVersions:    []string{">=1.2.2"},
				},
			},
			want: true,
		},
		{
			name: "multiple constraints",
			args: args{
				ver: "2.0.0",
				advisory: types.Advisory{
					VulnerableVersions: []string{">=1.7.0 <1.7.16", ">=1.8.0 <1.8.8", ">=2.0.0 <2.0.8", ">=3.0.0-beta.1 <3.0.0-beta.7"},
					PatchedVersions:    []string{">=3.0.0-beta.7", ">=2.0.8 <3.0.0-beta.1", ">=1.8.8 <2.0.0", ">=1.7.16 <1.8.0"},
				},
			},
			want: true,
		},
		{
			name: "invalid version",
			args: args{
				ver: "1.2..4",
				advisory: types.Advisory{
					VulnerableVersions: []string{"<1.0.0"},
				},
			},
			want: false,
		},
		{
			name: "improper constraint",
			args: args{
				ver: "1.2.3",
				advisory: types.Advisory{
					VulnerableVersions: []string{"*"},
					PatchedVersions:    nil,
				},
			},
			want: false,
		},
		{
			name: "empty patched version",
			args: args{
				ver: "1.2.3",
				advisory: types.Advisory{
					VulnerableVersions: []string{"<=99.999.99999"},
					PatchedVersions:    []string{""},
				},
			},
			want: true,
		},
		{
			name: "empty vulnerable & patched version",
			args: args{
				ver: "1.2.3",
				advisory: types.Advisory{
					VulnerableVersions: []string{""},
					PatchedVersions:    []string{""},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := compare.GenericComparer{}
			got := v.IsVulnerable(tt.args.ver, tt.args.advisory)
			assert.Equal(t, tt.want, got)
		})
	}
}
