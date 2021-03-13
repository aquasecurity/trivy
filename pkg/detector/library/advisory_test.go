package library_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/library"
	"github.com/aquasecurity/trivy/pkg/detector/library/bundler"
	"github.com/aquasecurity/trivy/pkg/detector/library/comparer"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestAdvisory_DetectVulnerabilities(t *testing.T) {
	type args struct {
		pkgName string
		pkgVer  string
	}
	tests := []struct {
		name      string
		fixtures  []string
		ecosystem string
		comparer  comparer.Comparer
		args      args
		want      []types.DetectedVulnerability
		wantErr   string
	}{
		{
			name:      "happy path",
			fixtures:  []string{"testdata/fixtures/php.yaml"},
			ecosystem: vulnerability.Composer,
			comparer:  comparer.GenericComparer{},
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
				},
			},
		},
		{
			name:      "no patched versions in the advisory",
			fixtures:  []string{"testdata/fixtures/php.yaml"},
			ecosystem: vulnerability.Composer,
			comparer:  comparer.GenericComparer{},
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
				},
			},
		},
		{
			name:      "no vulnerable versions in the advisory",
			fixtures:  []string{"testdata/fixtures/ruby.yaml"},
			ecosystem: vulnerability.RubyGems,
			comparer:  bundler.RubyGemsComparer{},
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
				},
			},
		},
		{
			name:      "no vulnerability",
			fixtures:  []string{"testdata/fixtures/php.yaml"},
			ecosystem: vulnerability.Composer,
			comparer:  comparer.GenericComparer{},
			args: args{
				pkgName: "symfony/symfony",
				pkgVer:  "4.4.7",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize DB
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			adv := library.NewAdvisory(tt.ecosystem, tt.comparer)
			got, err := adv.DetectVulnerabilities(tt.args.pkgName, tt.args.pkgVer)

			switch {
			case tt.wantErr != "":
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			default:
				assert.NoError(t, err)
			}

			// Compare
			assert.Equal(t, tt.want, got)
		})
	}
}
