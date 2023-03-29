package cargo

import (
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMatchVersion(t *testing.T) {
	tests := []struct {
		name       string
		version    string // version from Cargo.lock
		constraint string // version from Cargo.toml
		want       bool
	}{
		{
			name:       "> major version",
			version:    "2.5.0",
			constraint: "> 2",
			want:       true,
		},
		{
			name:       ">= minor version",
			version:    "2.4.2",
			constraint: ">= 2.4",
			want:       true,
		},
		{
			name:       "< patch version",
			version:    "2.5.0",
			constraint: "< 2.5.0",
			want:       false,
		},
		{
			name:       "= major version",
			version:    "2.5.0",
			constraint: "= 2",
			want:       true,
		},
		{
			name:       "= minor version",
			version:    "2.5.0",
			constraint: "= 2.4",
			want:       false,
		},
		{
			name:       "^ minor version",
			version:    "2.5.0",
			constraint: "^2.4",
			want:       true,
		},
		{
			name:       "'' major version",
			version:    "2.5.0",
			constraint: "2",
			want:       true,
		},
		{
			name:       "'' minor version",
			version:    "2.5.0",
			constraint: "1.4",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := cargoAnalyzer{
				comparer: compare.GenericComparer{},
			}
			match, _ := a.matchVersion(tt.version, tt.constraint)
			assert.Equal(t, tt.want, match)
		})
	}
}
