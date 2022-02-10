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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := maven.Comparer{}
			got := c.IsVulnerable(tt.args.currentVersion, tt.args.advisory)
			assert.Equal(t, tt.want, got)
		})
	}
}
