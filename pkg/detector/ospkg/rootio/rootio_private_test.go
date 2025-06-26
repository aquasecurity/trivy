package rootio

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestScanner_IsVulnerable(t *testing.T) {
	tests := []struct {
		name             string
		installedVersion string
		vulnerableRanges []string
		want             bool
	}{
		// Case 1
		{"1-a", "1.0.0", []string{"<1.0.0-2"}, true},
		{"1-b", "1.0.0-2", []string{"<1.0.0-2"}, false},
		{"1-c", "1.0.0-2", []string{"<1.0.0-2.root.io", ">=1.0.0-2 <1.0.0-3"}, true},
		{"1-d", "1.0.0-3", []string{"<1.0.0-2.root.io", ">=1.0.0-2 <1.0.0-3"}, false},

		// Case 2
		{"2-a", "1.0.0-1", []string{"<1.0.0-2"}, true},
		{"2-b", "1.0.0-2", []string{"<1.0.0-2"}, false},

		// Case 3
		{"3-a", "1.0.0-1", []string{"<1.0.0-2.root.io"}, true},
		// Impossible to detect
		// {"3-b", "1.0.0-3", []string{"<1.0.0-2.root.io"}, false},

		// Case 4
		{"4", "1.0.0", []string{}, true},

		// Case 5
		{"5-a", "1.0.0-1.root.io", []string{"<1.0.0-2.root.io", ">=1.0.0-2 <1.0.0-2"}, true},
		{"5-b", "1.0.0-2.root.io", []string{"<1.0.0-2.root.io", ">=1.0.0-2 <1.0.0-2"}, false},
		{"5-c", "1.0.0-1.root.io", []string{"<1.0.0-2.root.io", ">=1.0.0-2 <1.0.0-3"}, true},
		// Incorrect range. Ranges are intersect. Debian order is 1.0.0-2 < 1.0.0-2.root.io < 1.0.0-3.
		// {"5-d", "1.0.0-2.root.io", []string{"<1.0.0-2.root.io", ">=1.0.0-2 <1.0.0-3"}, false},

		// Case 6
		{"6-a", "1.0.0-1.root.io", []string{"<1.0.0-2.root.io"}, true},
		{"6-b", "1.0.0-2.root.io", []string{"<1.0.0-2.root.io"}, false},

		// Case 7
		{"7-a", "1.0.0-1.root.io", []string{"<1.0.0-2"}, true},
		{"7-b", "1.0.0-3.root.io", []string{"<1.0.0-2"}, false},

		// Case 8
		{"8", "1.0.0-1.root.io", []string{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewScanner(ftypes.Debian)
			vulnerable := scanner.isVulnerable(t.Context(), tt.installedVersion, types.Advisory{VulnerableVersions: tt.vulnerableRanges})
			require.Equal(t, tt.want, vulnerable)
		})
	}
}
