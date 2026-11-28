package flag_test

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/samber/lo"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/licensing/expression"
)

func TestLicenseFlagGroup_ToOptions(t *testing.T) {
	tests := []struct {
		name           string
		config         string
		wantCategories map[types.LicenseCategory][]string
		wantErr        string
	}{
		{
			name:   "default categories",
			config: "{}",
		},
		{
			name: "stricter category overrides default",
			config: `
license:
  forbidden: [MIT]
`,
			wantCategories: map[types.LicenseCategory][]string{
				types.CategoryForbidden: {expression.MIT},
				types.CategoryNotice:    lo.Without(expression.NoticeLicenses, expression.MIT),
			},
		},
		{
			name: "laxer category overrides default",
			config: `
license:
  permissive: [AGPL-3.0]
`,
			wantCategories: map[types.LicenseCategory][]string{
				types.CategoryForbidden:  lo.Without(expression.ForbiddenLicenses, expression.AGPL30),
				types.CategoryPermissive: {expression.AGPL30},
			},
		},
		{
			name: "stricter category overrides default case insensitively",
			config: `
license:
  forbidden: [mIt]
`,
			wantCategories: map[types.LicenseCategory][]string{
				types.CategoryForbidden: {"mIt"},
				types.CategoryNotice:    lo.Without(expression.NoticeLicenses, expression.MIT),
			},
		},
		{
			name: "laxer category overrides default case insensitively",
			config: `
license:
  permissive: [agpl-3.0]
`,
			wantCategories: map[types.LicenseCategory][]string{
				types.CategoryForbidden:  lo.Without(expression.ForbiddenLicenses, expression.AGPL30),
				types.CategoryPermissive: {"agpl-3.0"},
			},
		},
		{
			name: "explicit list replaces rather than extends defaults",
			config: `
license:
  restricted: [Custom-License]
`,
			wantCategories: map[types.LicenseCategory][]string{
				types.CategoryRestricted: {"Custom-License"},
			},
		},
		{
			name: "explicit empty list clears category",
			config: `
license:
  reciprocal: []
`,
			wantCategories: map[types.LicenseCategory][]string{
				types.CategoryReciprocal: {},
			},
		},
		{
			name: "all categories can be cleared",
			config: `
license:
  forbidden: []
  restricted: []
  reciprocal: []
  notice: []
  permissive: []
  unencumbered: []
`,
			wantCategories: map[types.LicenseCategory][]string{
				types.CategoryForbidden:    {},
				types.CategoryRestricted:   {},
				types.CategoryReciprocal:   {},
				types.CategoryNotice:       {},
				types.CategoryPermissive:   {},
				types.CategoryUnencumbered: {},
			},
		},
		{
			name: "multiple explicit categories override defaults",
			config: `
license:
  restricted: [MIT]
  unencumbered: [AGPL-3.0]
`,
			wantCategories: map[types.LicenseCategory][]string{
				types.CategoryForbidden:    lo.Without(expression.ForbiddenLicenses, expression.AGPL30),
				types.CategoryRestricted:   {expression.MIT},
				types.CategoryNotice:       lo.Without(expression.NoticeLicenses, expression.MIT),
				types.CategoryUnencumbered: {expression.AGPL30},
			},
		},
		{
			name: "text patterns differing in case remain distinct",
			config: `
license:
  forbidden: ['text://^\D+$']
  notice: ['text://^\d+$']
`,
			wantCategories: map[types.LicenseCategory][]string{
				types.CategoryForbidden: {`text://^\D+$`},
				types.CategoryNotice:    {`text://^\d+$`},
			},
		},
		{
			name: "duplicate explicit assignments are rejected",
			config: `
license:
  permissive: [MIT]
  forbidden: [MIT]
`,
			wantErr: `unable to convert flags to options: license "MIT" is explicitly configured in both "forbidden" and "permissive" categories`,
		},
		{
			name: "duplicate explicit assignments are case insensitive",
			config: `
license:
  forbidden: [MIT]
  permissive: [mit]
`,
			wantErr: `unable to convert flags to options: license "mit" is explicitly configured in both "forbidden" and "permissive" categories`,
		},
		{
			name: "conflict order is stable across multiple categories",
			config: `
license:
  unencumbered: [Custom-License]
  notice: [Custom-License]
  reciprocal: [Custom-License]
`,
			wantErr: `unable to convert flags to options: license "Custom-License" is explicitly configured in both "reciprocal" and "notice" categories`,
		},
		{
			name: "duplicates within one explicit category are allowed",
			config: `
license:
  forbidden: [MIT, mit]
`,
			wantCategories: map[types.LicenseCategory][]string{
				types.CategoryForbidden: {"MIT", "mit"},
				types.CategoryNotice:    lo.Without(expression.NoticeLicenses, expression.MIT),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(viper.Reset)
			viper.SetConfigType("yaml")
			require.NoError(t, viper.ReadConfig(strings.NewReader(tt.config)))

			want := defaultLicenseCategories()
			maps.Copy(want, tt.wantCategories)

			flags := flag.Flags{flag.NewLicenseFlagGroup()}
			got, err := flags.ToOptions(nil)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, want, got.LicenseCategories)
		})
	}
}

func TestLicenseFlagGroup_ToOptions_unchangedDefaults(t *testing.T) {
	t.Cleanup(viper.Reset)

	want := defaultLicenseCategories()
	viper.Set(flag.LicenseForbidden.ConfigName, []string{"mIt"})
	viper.Set(flag.LicensePermissive.ConfigName, []string{"agpl-3.0"})

	flags := flag.Flags{flag.NewLicenseFlagGroup()}
	got, err := flags.ToOptions(nil)
	require.NoError(t, err)
	assert.Equal(t, want, defaultLicenseCategories())

	// Options must not share backing arrays with either built-in or flag defaults.
	for _, licenses := range got.LicenseCategories {
		if len(licenses) > 0 {
			licenses[0] = "Changed-License"
		}
	}
	assert.Equal(t, want, defaultLicenseCategories())
	assert.Equal(t, want, map[types.LicenseCategory][]string{
		types.CategoryForbidden:    flag.LicenseForbidden.Default,
		types.CategoryRestricted:   flag.LicenseRestricted.Default,
		types.CategoryReciprocal:   flag.LicenseReciprocal.Default,
		types.CategoryNotice:       flag.LicenseNotice.Default,
		types.CategoryPermissive:   flag.LicensePermissive.Default,
		types.CategoryUnencumbered: flag.LicenseUnencumbered.Default,
	})

	// A later conversion without configuration still gets the original defaults.
	viper.Reset()
	flags = flag.Flags{flag.NewLicenseFlagGroup()}
	got, err = flags.ToOptions(nil)
	require.NoError(t, err)
	assert.Equal(t, want, got.LicenseCategories)
}

func TestLicenseFlagGroup_ToOptions_otherOptions(t *testing.T) {
	t.Cleanup(viper.Reset)
	viper.Set(flag.LicenseFull.ConfigName, true)
	viper.Set(flag.IgnoredLicenses.ConfigName, []string{expression.MIT})
	viper.Set(flag.LicenseConfidenceLevel.ConfigName, 0.95)

	flags := flag.Flags{flag.NewLicenseFlagGroup()}
	got, err := flags.ToOptions(nil)
	require.NoError(t, err)
	assert.Equal(t, flag.LicenseOptions{
		LicenseFull:            true,
		IgnoredLicenses:        []string{expression.MIT},
		LicenseConfidenceLevel: 0.95,
		LicenseCategories:      defaultLicenseCategories(),
	}, got.LicenseOptions)
}

func defaultLicenseCategories() map[types.LicenseCategory][]string {
	return map[types.LicenseCategory][]string{
		types.CategoryForbidden:    slices.Clone(expression.ForbiddenLicenses),
		types.CategoryRestricted:   slices.Clone(expression.RestrictedLicenses),
		types.CategoryReciprocal:   slices.Clone(expression.ReciprocalLicenses),
		types.CategoryNotice:       slices.Clone(expression.NoticeLicenses),
		types.CategoryPermissive:   slices.Clone(expression.PermissiveLicenses),
		types.CategoryUnencumbered: slices.Clone(expression.UnencumberedLicenses),
	}
}
