package library_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/library"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestDriver_Detect(t *testing.T) {
	type args struct {
		pkgName string
		pkgVer  string
	}
	tests := []struct {
		name     string
		fixtures []string
		libType  string
		args     args
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
			args: args{
				pkgName: "symfony/symfony",
				pkgVer:  "4.2.6",
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2019-10909",
					PkgName:          "symfony/symfony",
					InstalledVersion: "4.2.6",
					FixedVersion:     "4.2.7",
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
			args: args{
				pkgName: "github.com/Masterminds/vcs",
				pkgVer:  "v1.13.1",
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2022-21235",
					PkgName:          "github.com/Masterminds/vcs",
					InstalledVersion: "v1.13.1",
					FixedVersion:     "v1.13.2",
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
			args: args{
				pkgName: "symfony/symfony",
				pkgVer:  "4.2.6",
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
			args: args{
				pkgName: "symfony/symfony",
				pkgVer:  "4.4.6",
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2020-5275",
					PkgName:          "symfony/symfony",
					InstalledVersion: "4.4.6",
					FixedVersion:     "4.4.7",
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
			args: args{
				pkgName: "activesupport",
				pkgVer:  "4.1.1",
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2015-3226",
					PkgName:          "activesupport",
					InstalledVersion: "4.1.1",
					FixedVersion:     ">= 4.2.2, ~> 4.1.11",
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
			args: args{
				pkgName: "symfony/symfony",
				pkgVer:  "4.4.7",
			},
		},
		{
			name:     "malformed JSON",
			fixtures: []string{"testdata/fixtures/invalid-type.yaml"},
			libType:  ftypes.Composer,
			args: args{
				pkgName: "symfony/symfony",
				pkgVer:  "5.1.5",
			},
			wantErr: "failed to unmarshal advisory JSON",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize DB
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			driver, err := library.NewDriver(tt.libType)
			require.NoError(t, err)

			got, err := driver.DetectVulnerabilities("", tt.args.pkgName, tt.args.pkgVer)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			// Compare
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
