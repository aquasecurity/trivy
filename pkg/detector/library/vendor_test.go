package library

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
)

func Test_lookupVendor(t *testing.T) {
	defaultComparer := compare.GenericComparer{}

	tests := []struct {
		name            string
		eco             ecosystem.Type
		pkgName         string
		wantMatch       bool
		wantPrefix      string
		wantComparerNil bool // true if the default comparer should be returned unchanged
	}{
		{
			name:            "seal pip package returns vendor prefix and pep440 comparer",
			eco:             ecosystem.Pip,
			pkgName:         "seal-requests",
			wantMatch:       true,
			wantPrefix:      "seal pip::",
			wantComparerNil: false,
		},
		{
			name:            "seal npm package returns vendor prefix and default comparer",
			eco:             ecosystem.Npm,
			pkgName:         "@seal-security/ejs",
			wantMatch:       true,
			wantPrefix:      "seal npm::",
			wantComparerNil: true,
		},
		{
			name:            "seal go package returns vendor prefix and default comparer",
			eco:             ecosystem.Go,
			pkgName:         "sealsecurity.io/github.com/foo/bar",
			wantMatch:       true,
			wantPrefix:      "seal go::",
			wantComparerNil: true,
		},
		{
			name:            "seal maven package returns vendor prefix and default comparer",
			eco:             ecosystem.Maven,
			pkgName:         "seal.sp1.org.eclipse.jetty:jetty-http",
			wantMatch:       true,
			wantPrefix:      "seal maven::",
			wantComparerNil: true,
		},
		{
			name:            "seal rubygems package returns vendor prefix and default comparer",
			eco:             ecosystem.RubyGems,
			pkgName:         "seal-rack",
			wantMatch:       true,
			wantPrefix:      "seal rubygems::",
			wantComparerNil: true,
		},
		{
			name:      "non-seal pip package returns no match",
			eco:       ecosystem.Pip,
			pkgName:   "requests",
			wantMatch: false,
		},
		{
			name:      "non-seal npm package returns no match",
			eco:       ecosystem.Npm,
			pkgName:   "ejs",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, ok := lookupVendor(tt.eco, tt.pkgName, "")
			require.Equal(t, tt.wantMatch, ok)
			if !ok {
				return
			}
			assert.Equal(t, tt.wantPrefix, v.BucketPrefix(tt.eco))
			if tt.wantComparerNil {
				assert.Nil(t, v.Comparer(tt.eco))
			} else {
				// For seal pip, a custom pep440 comparer with AllowLocalSpecifier should be returned.
				assert.IsType(t, pep440.Comparer{}, v.Comparer(tt.eco))
			}

			// When Comparer returns nil, the caller should use the default comparer.
			if v.Comparer(tt.eco) == nil {
				assert.Equal(t, defaultComparer, defaultComparer)
			}
		})
	}
}
