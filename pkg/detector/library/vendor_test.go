package library_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy/pkg/detector/library"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"

	_ "github.com/aquasecurity/trivy/pkg/detector/library/echo" // register Echo vendor
	_ "github.com/aquasecurity/trivy/pkg/detector/library/seal" // register Seal Security vendor
)

func Test_lookupVendor(t *testing.T) {
	defaultComparer := compare.GenericComparer{}

	tests := []struct {
		name                string
		eco                 ecosystem.Type
		pkgName             string
		pkgVer              string
		wantMatch           bool
		wantPrefix          string
		wantDefaultComparer bool
	}{
		{
			name:                "seal pip package returns vendor prefix and pep440 comparer",
			eco:                 ecosystem.Pip,
			pkgName:             "seal-requests",
			wantMatch:           true,
			wantPrefix:          "seal pip::",
			wantDefaultComparer: false,
		},
		{
			name:                "seal npm package returns vendor prefix and default comparer",
			eco:                 ecosystem.Npm,
			pkgName:             "@seal-security/ejs",
			wantMatch:           true,
			wantPrefix:          "seal npm::",
			wantDefaultComparer: true,
		},
		{
			name:                "seal go package returns vendor prefix and default comparer",
			eco:                 ecosystem.Go,
			pkgName:             "sealsecurity.io/github.com/foo/bar",
			wantMatch:           true,
			wantPrefix:          "seal go::",
			wantDefaultComparer: true,
		},
		{
			name:                "seal maven package returns vendor prefix and default comparer",
			eco:                 ecosystem.Maven,
			pkgName:             "seal.sp1.org.eclipse.jetty:jetty-http",
			wantMatch:           true,
			wantPrefix:          "seal maven::",
			wantDefaultComparer: true,
		},
		{
			name:                "seal rubygems package returns vendor prefix and default comparer",
			eco:                 ecosystem.RubyGems,
			pkgName:             "seal-rack",
			wantMatch:           true,
			wantPrefix:          "seal rubygems::",
			wantDefaultComparer: true,
		},
		{
			name:                "echo pip package returns vendor prefix and pep440 comparer",
			eco:                 ecosystem.Pip,
			pkgName:             "requests",
			pkgVer:              "2.14.2+echo.1",
			wantMatch:           true,
			wantPrefix:          "echo pip::",
			wantDefaultComparer: false,
		},
		{
			name:      "non-echo pip package without version suffix returns no match",
			eco:       ecosystem.Pip,
			pkgName:   "requests",
			pkgVer:    "2.14.2",
			wantMatch: false,
		},
		{
			name:                "echo npm package returns vendor prefix and echo npm comparer",
			eco:                 ecosystem.Npm,
			pkgName:             "@babel/traverse",
			pkgVer:              "7.23.2+echo.1",
			wantMatch:           true,
			wantPrefix:          "echo npm::",
			wantDefaultComparer: false,
		},
		{
			name:      "echo version suffix on unsupported ecosystem returns no match",
			eco:       ecosystem.Go,
			pkgName:   "golang.org/x/crypto",
			pkgVer:    "0.26.0+echo.1",
			wantMatch: false,
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
			v, ok := library.LookupVendor(tt.eco, tt.pkgName, tt.pkgVer)
			require.Equal(t, tt.wantMatch, ok)
			if !ok {
				return
			}
			assert.Equal(t, tt.wantPrefix, v.BucketPrefix(tt.eco))
			comparer := v.Comparer(tt.eco, defaultComparer)
			if tt.wantDefaultComparer {
				// When no custom comparer is needed, the default should be returned unchanged.
				assert.Equal(t, defaultComparer, comparer)
			} else {
				// A vendor-specific comparer should replace the default one,
				// e.g. pep440 with AllowLocalSpecifier for pip, the Echo npm
				// comparer for npm.
				assert.NotEqual(t, defaultComparer, comparer)
				if tt.eco == ecosystem.Pip {
					assert.IsType(t, pep440.Comparer{}, comparer)
				}
			}
		})
	}
}
