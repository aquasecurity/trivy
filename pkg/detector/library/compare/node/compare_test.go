package node_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/detector/library/compare/node"
)

func TestComparer_MatchVersion(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		constraint string
		want       bool
	}{
		{name: "affected release line", version: "26.3.0", constraint: "26.x", want: true},
		{name: "patched runtime", version: "26.3.1", constraint: "<26.3.1", want: false},
		{name: "prerelease", version: "22.0.0-rc.1", constraint: "<22.0.0", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (node.Comparer{}).MatchVersion(tt.version, tt.constraint)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
