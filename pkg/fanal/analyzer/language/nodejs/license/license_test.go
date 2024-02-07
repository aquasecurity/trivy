package license_test

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/license"
	"github.com/aquasecurity/trivy/pkg/mapfs"
)

func Test_ParseLicenses(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		want    map[string][]types.License
		wantErr string
	}{
		{
			name: "happy",
			dir:  filepath.Join("testdata", "happy"),
			want: map[string][]types.License{
				"package-a@0.0.1": {
					{
						Type:  types.LicenseTypeName,
						Value: "CC-BY-SA-4.0",
					},
				},
				"package-b@0.0.1": {
					{
						Type:  types.LicenseTypeName,
						Value: "MIT",
					},
				},
				"package-c@0.0.1": {
					{
						Type:  types.LicenseTypeName,
						Value: "BSD-3-Clause",
					},
				},
				"package-d@0.0.1": {
					{
						Type:  types.LicenseTypeName,
						Value: "BSD-3-Clause",
					},
				},
				"package-e@0.0.1": {
					{
						Type:  types.LicenseTypeName,
						Value: "(GPL-3.0 OR LGPL-3.0 OR MPL-1.1 OR SEE LICENSE IN LICENSE)",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := mapfs.New()
			require.NoError(t, fsys.CopyFilesUnder(tt.dir))

			l := license.NewLicense(0.9)
			licenses, err := l.Traverse(fsys, ".")
			if tt.wantErr != "" {
				assert.ErrorContainsf(t, err, tt.wantErr, tt.name)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, licenses)
		})
	}
}
