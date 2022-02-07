package pep440_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
)

func TestPep440Comparer_IsVulnerable(t *testing.T) {
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
				currentVersion: "1.2.3a1",
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
					VulnerableVersions: []string{">=1.7.0 <1.7.16", ">=1.8.0 <1.8.8", ">=2.0.0 <2.0.8", ">=3.0.0b1 <3.0.0b7"},
					PatchedVersions:    []string{">=3.0.0b7", ">=2.0.8 <3.0.0b1", ">=1.8.8 <2.0.0", ">=1.7.16 <1.8.0"},
				},
			},
			want: true,
		},
		{
			name: "exact versions",
			args: args{
				currentVersion: "2.1.0.post1",
				advisory: dbTypes.Advisory{
					VulnerableVersions: []string{"2.1.0.post1", "2.0.0"},
					PatchedVersions:    []string{">=2.1.1"},
				},
			},
			want: true,
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := pep440.Comparer{}
			got := c.IsVulnerable(tt.args.currentVersion, tt.args.advisory)
			assert.Equal(t, tt.want, got)
		})
	}
}
