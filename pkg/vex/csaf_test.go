package vex

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/types"
)

func newTestCSAF(t *testing.T, path string) *CSAF {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	var adv csaf.Advisory
	require.NoError(t, json.Unmarshal(b, &adv))
	return newCSAF(adv, path)
}

func testComponent(t *testing.T, s string) *core.Component {
	t.Helper()
	p, err := purl.FromString(s)
	require.NoError(t, err)
	return &core.Component{PkgIdentifier: ftypes.PkgIdentifier{PURL: p.Unwrap()}}
}

func TestCSAF_NotAffected(t *testing.T) {
	const (
		direct     = "pkg:golang/github.com/aquasecurity/go-direct1@v2.0.0"
		transitive = "pkg:golang/github.com/aquasecurity/go-transitive@v4.0.0"
		other      = "pkg:golang/github.com/aquasecurity/other@v1.0.0"
	)
	vuln := types.DetectedVulnerability{VulnerabilityID: "CVE-2024-0001"}

	tests := []struct {
		name       string
		product    *core.Component
		subProduct *core.Component
		want       bool
	}{
		{
			name:       "relationship matches",
			product:    testComponent(t, direct),
			subProduct: testComponent(t, transitive),
			want:       true,
		},
		{
			name:       "nil sub-product does not panic and is not filtered",
			product:    testComponent(t, direct),
			subProduct: nil,
			want:       false,
		},
		{
			name:       "sub-product without PURL is not filtered",
			product:    testComponent(t, direct),
			subProduct: &core.Component{},
			want:       false,
		},
		{
			name:       "sub-product does not match",
			product:    testComponent(t, direct),
			subProduct: testComponent(t, other),
			want:       false,
		},
		{
			name:       "product does not match the relationship",
			product:    testComponent(t, other),
			subProduct: testComponent(t, transitive),
			want:       false,
		},
		{
			name:    "nil product",
			product: nil,
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := newTestCSAF(t, "testdata/csaf-relationships.json")
			assert.NotPanics(t, func() {
				_, got := v.NotAffected(vuln, tt.product, tt.subProduct)
				assert.Equal(t, tt.want, got)
			})
		})
	}
}
