package flag_test

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestPackageFlagGroup_ToOptions(t *testing.T) {
	type fields struct {
		pkgTypes         string
		pkgRelationships string
	}
	tests := []struct {
		name     string
		fields   fields
		want     flag.PackageOptions
		wantLogs []string
	}{
		{
			name:   "happy default (without flags)",
			fields: fields{},
			want:   flag.PackageOptions{},
		},
		{
			name: "happy path for OS packages",
			fields: fields{
				pkgTypes: "os",
			},
			want: flag.PackageOptions{
				PkgTypes: []string{
					types.PkgTypeOS,
				},
			},
		},
		{
			name: "happy path for library packages",
			fields: fields{
				pkgTypes: "library",
			},
			want: flag.PackageOptions{
				PkgTypes: []string{
					types.PkgTypeLibrary,
				},
			},
		},
		{
			name: "root and indirect relationships",
			fields: fields{
				pkgRelationships: "root,indirect",
			},
			want: flag.PackageOptions{
				PkgRelationships: []ftypes.Relationship{
					ftypes.RelationshipRoot,
					ftypes.RelationshipIndirect,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(viper.Reset)

			setValue(flag.PkgTypesFlag.ConfigName, tt.fields.pkgTypes)
			setValue(flag.PkgRelationshipsFlag.ConfigName, tt.fields.pkgRelationships)

			// Assert options
			f := &flag.PackageFlagGroup{
				PkgTypes:         flag.PkgTypesFlag.Clone(),
				PkgRelationships: flag.PkgRelationshipsFlag.Clone(),
			}

			got, err := f.ToOptions()
			require.NoError(t, err)
			assert.EqualExportedValuesf(t, tt.want, got, "PackageFlagGroup")
		})
	}
}
