package library

import (
	"testing"

	"github.com/stretchr/testify/assert"

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
		wantPrefix      string
		wantComparerNil bool // true if the default comparer should be returned unchanged
	}{
		{
			name:            "seal pip package returns vendor prefix and pep440 comparer",
			eco:             ecosystem.Pip,
			pkgName:         "seal-requests",
			wantPrefix:      "seal pip::",
			wantComparerNil: false,
		},
		{
			name:            "seal npm package returns vendor prefix and default comparer",
			eco:             ecosystem.Npm,
			pkgName:         "@seal-security/ejs",
			wantPrefix:      "seal npm::",
			wantComparerNil: true,
		},
		{
			name:            "seal go package returns vendor prefix and default comparer",
			eco:             ecosystem.Go,
			pkgName:         "sealsecurity.io/github.com/foo/bar",
			wantPrefix:      "seal go::",
			wantComparerNil: true,
		},
		{
			name:            "seal maven package returns vendor prefix and default comparer",
			eco:             ecosystem.Maven,
			pkgName:         "seal.sp1.org.eclipse.jetty:jetty-http",
			wantPrefix:      "seal maven::",
			wantComparerNil: true,
		},
		{
			name:            "seal rubygems package returns vendor prefix and default comparer",
			eco:             ecosystem.RubyGems,
			pkgName:         "seal-rack",
			wantPrefix:      "seal rubygems::",
			wantComparerNil: true,
		},
		{
			name:            "non-seal pip package returns standard prefix",
			eco:             ecosystem.Pip,
			pkgName:         "requests",
			wantPrefix:      "pip::",
			wantComparerNil: true,
		},
		{
			name:            "non-seal npm package returns standard prefix",
			eco:             ecosystem.Npm,
			pkgName:         "ejs",
			wantPrefix:      "npm::",
			wantComparerNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPrefix, gotComparer := lookupVendor(tt.eco, tt.pkgName, "", defaultComparer)
			assert.Equal(t, tt.wantPrefix, gotPrefix)
			if tt.wantComparerNil {
				assert.Equal(t, defaultComparer, gotComparer)
			} else {
				// For seal pip, a custom pep440 comparer with AllowLocalSpecifier should be returned.
				assert.IsType(t, pep440.Comparer{}, gotComparer)
			}
		})
	}
}
