package generic_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/library/generic"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestDriver_Detect(t *testing.T) {
	tests := []struct {
		name     string
		fixtures []string
		libType  ftypes.LangType
		pkg      ftypes.Package
		want     []types.DetectedVulnerability
		wantErr  string
	}{
		{
			name: "happy path",
			fixtures: []string{
				"testdata/fixtures/php.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			libType: ftypes.Composer,
			pkg: ftypes.Package{
				Name:       "symfony/symfony",
				Version:    "4.2.6",
				Layer:      ftypes.Layer{Digest: "sha256:layer"},
				FilePath:   "/path/to/composer.lock",
				Identifier: ftypes.PkgIdentifier{BOMRef: "bom-ref-1"},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2019-10909",
					PkgName:          "symfony/symfony",
					InstalledVersion: "4.2.6",
					FixedVersion:     "4.2.7",
					Layer:            ftypes.Layer{Digest: "sha256:layer"},
					PkgPath:          "/path/to/composer.lock",
					PkgIdentifier:    ftypes.PkgIdentifier{BOMRef: "bom-ref-1"},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.GLAD,
						Name: "GitLab Advisory Database Community",
						URL:  "https://gitlab.com/gitlab-org/advisories-community",
					},
				},
			},
		},
		{
			name: "case-sensitive go package",
			fixtures: []string{
				"testdata/fixtures/go.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			libType: ftypes.GoModule,
			pkg: ftypes.Package{
				Name:       "github.com/Masterminds/vcs",
				Version:    "v1.13.1",
				Layer:      ftypes.Layer{Digest: "sha256:layer"},
				FilePath:   "/path/to/go.mod",
				Identifier: ftypes.PkgIdentifier{BOMRef: "bom-ref-1"},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2022-21235",
					PkgName:          "github.com/Masterminds/vcs",
					InstalledVersion: "v1.13.1",
					FixedVersion:     "v1.13.2",
					Layer:            ftypes.Layer{Digest: "sha256:layer"},
					PkgPath:          "/path/to/go.mod",
					PkgIdentifier:    ftypes.PkgIdentifier{BOMRef: "bom-ref-1"},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.GLAD,
						Name: "GitLab Advisory Database Community",
						URL:  "https://gitlab.com/gitlab-org/advisories-community",
					},
				},
			},
		},
		{
			name:     "non-prefixed buckets",
			fixtures: []string{"testdata/fixtures/php-without-prefix.yaml"},
			libType:  ftypes.Composer,
			pkg: ftypes.Package{
				Name:       "symfony/symfony",
				Version:    "4.2.6",
				Layer:      ftypes.Layer{Digest: "sha256:layer"},
				FilePath:   "/path/to/composer.lock",
				Identifier: ftypes.PkgIdentifier{BOMRef: "bom-ref-1"},
			},
			want: nil,
		},
		{
			name: "no patched versions in the advisory",
			fixtures: []string{
				"testdata/fixtures/php.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			libType: ftypes.Composer,
			pkg: ftypes.Package{
				Name:       "symfony/symfony",
				Version:    "4.4.6",
				Layer:      ftypes.Layer{Digest: "sha256:layer"},
				FilePath:   "/path/to/composer.lock",
				Identifier: ftypes.PkgIdentifier{BOMRef: "bom-ref-1"},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2020-5275",
					PkgName:          "symfony/symfony",
					InstalledVersion: "4.4.6",
					FixedVersion:     "4.4.7",
					Layer:            ftypes.Layer{Digest: "sha256:layer"},
					PkgPath:          "/path/to/composer.lock",
					PkgIdentifier:    ftypes.PkgIdentifier{BOMRef: "bom-ref-1"},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.PhpSecurityAdvisories,
						Name: "PHP Security Advisories Database",
						URL:  "https://github.com/FriendsOfPHP/security-advisories",
					},
				},
			},
		},
		{
			name: "no vulnerable versions in the advisory",
			fixtures: []string{
				"testdata/fixtures/ruby.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			libType: ftypes.Bundler,
			pkg: ftypes.Package{
				Name:       "activesupport",
				Version:    "4.1.1",
				Layer:      ftypes.Layer{Digest: "sha256:layer"},
				FilePath:   "/path/to/Gemfile.lock",
				Identifier: ftypes.PkgIdentifier{BOMRef: "bom-ref-1"},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2015-3226",
					PkgName:          "activesupport",
					InstalledVersion: "4.1.1",
					FixedVersion:     ">= 4.2.2, ~> 4.1.11",
					Layer:            ftypes.Layer{Digest: "sha256:layer"},
					PkgPath:          "/path/to/Gemfile.lock",
					PkgIdentifier:    ftypes.PkgIdentifier{BOMRef: "bom-ref-1"},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.RubySec,
						Name: "Ruby Advisory Database",
						URL:  "https://github.com/rubysec/ruby-advisory-db",
					},
				},
			},
		},
		{
			name:     "no vulnerability",
			fixtures: []string{"testdata/fixtures/php.yaml"},
			libType:  ftypes.Composer,
			pkg: ftypes.Package{
				Name:       "symfony/symfony",
				Version:    "4.4.7",
				Layer:      ftypes.Layer{Digest: "sha256:layer"},
				FilePath:   "/path/to/composer.lock",
				Identifier: ftypes.PkgIdentifier{BOMRef: "bom-ref-1"},
			},
		},
		{
			name:     "malformed JSON",
			fixtures: []string{"testdata/fixtures/invalid-type.yaml"},
			libType:  ftypes.Composer,
			pkg: ftypes.Package{
				Name:       "symfony/symfony",
				Version:    "5.1.5",
				Layer:      ftypes.Layer{Digest: "sha256:layer"},
				FilePath:   "/path/to/composer.lock",
				Identifier: ftypes.PkgIdentifier{BOMRef: "bom-ref-1"},
			},
			wantErr: "json unmarshal error",
		},
		{
			name: "duplicated version in advisory",
			fixtures: []string{
				"testdata/fixtures/pip.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			libType: ftypes.PythonPkg,
			pkg: ftypes.Package{
				Name:       "Django",
				Version:    "4.2.1",
				Layer:      ftypes.Layer{Digest: "sha256:layer"},
				FilePath:   "/path/to/requirements.txt",
				Identifier: ftypes.PkgIdentifier{BOMRef: "bom-ref-1"},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2023-36053",
					PkgName:          "Django",
					InstalledVersion: "4.2.1",
					FixedVersion:     "4.2.3",
					Layer:            ftypes.Layer{Digest: "sha256:layer"},
					PkgPath:          "/path/to/requirements.txt",
					PkgIdentifier:    ftypes.PkgIdentifier{BOMRef: "bom-ref-1"},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory Pip",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip",
					},
				},
			},
		},
		{
			name: "Custom data for vulnerability",
			fixtures: []string{
				"testdata/fixtures/go-custom-data.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			libType: ftypes.GoBinary,
			pkg: ftypes.Package{
				Name:       "github.com/docker/docker",
				Version:    "23.0.14",
				Layer:      ftypes.Layer{Digest: "sha256:layer"},
				FilePath:   "/path/to/go.mod",
				Identifier: ftypes.PkgIdentifier{BOMRef: "bom-ref-1"},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "GHSA-v23v-6jw2-98fq",
					PkgName:          "github.com/docker/docker",
					InstalledVersion: "23.0.14",
					FixedVersion:     "23.0.15, 26.1.5, 27.1.1, 25.0.6",
					Layer:            ftypes.Layer{Digest: "sha256:layer"},
					PkgPath:          "/path/to/go.mod",
					PkgIdentifier:    ftypes.PkgIdentifier{BOMRef: "bom-ref-1"},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory Go",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Ago",
					},
					Custom: map[string]any{"Severity": 2.0},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize DB
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			driver, ok := generic.NewScanner(tt.libType)
			require.True(t, ok)

			// Pass the package directly
			got, err := driver.Detect(t.Context(), tt.pkg)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			// Compare
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
