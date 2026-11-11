package composer_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/composer"
)

func TestComparer_IsVulnerable(t *testing.T) {
	// CVE-2024-34102 in magento/product-community-edition
	// https://github.com/FriendsOfPHP/security-advisories/blob/master/magento/product-community-edition/CVE-2024-34102.yaml
	cosmicSting := dbTypes.Advisory{
		VulnerableVersions: []string{
			"<2.4.4",
			">=2.4.4, <2.4.4-p9",
			">=2.4.5, <2.4.5-p8",
			">=2.4.6, <2.4.6-p6",
			">=2.4.7, <2.4.7-p1",
		},
	}

	tests := []struct {
		name           string
		currentVersion string
		advisory       dbTypes.Advisory
		want           bool
	}{
		{
			name:           "happy path",
			currentVersion: "4.2.6",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{">= 4.2.0, < 4.2.7"},
				PatchedVersions:    []string{"4.2.7"},
			},
			want: true,
		},
		{
			name:           "patched version",
			currentVersion: "4.2.7",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{">= 4.2.0, < 4.2.7"},
				PatchedVersions:    []string{"4.2.7"},
			},
			want: false,
		},
		{
			name:           "no patched versions",
			currentVersion: "4.4.6",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{">= 4.4.0, < 4.4.7"},
			},
			want: true,
		},
		{
			name:           "version prefix",
			currentVersion: "v5.4.24",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{">=5.4.0, <5.4.25"},
			},
			want: true,
		},
		{
			name:           "upper-case version prefix",
			currentVersion: "V0.7.5",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"<0.25.5"},
			},
			want: true,
		},
		{
			name:           "numbers left out are zero",
			currentVersion: "2.3",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"=2.3.0.0"},
			},
			want: true,
		},
		{
			name:           "four numbers",
			currentVersion: "3.7.510.6",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"<3.7.510.7"},
			},
			want: true,
		},
		{
			name:           "build metadata is ignored",
			currentVersion: "1.0.0+build.5",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"=1.0.0"},
			},
			want: true,
		},
		{
			name:           "alternatives in one range",
			currentVersion: "2.67.3",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"<2.66.7||>=2.67.0 <2.67.4"},
			},
			want: true,
		},

		// A patch follows the release it patches.
		{
			name:           "release without the patch",
			currentVersion: "2.4.7",
			advisory:       cosmicSting,
			want:           true,
		},
		{
			name:           "release with an earlier patch",
			currentVersion: "2.4.6-p5",
			advisory:       cosmicSting,
			want:           true,
		},
		{
			name:           "release with the patch",
			currentVersion: "2.4.4-p9",
			advisory:       cosmicSting,
			want:           false,
		},
		{
			name:           "release with a later patch",
			currentVersion: "2.4.7-p3",
			advisory:       cosmicSting,
			want:           false,
		},
		{
			name:           "release before all patched ones",
			currentVersion: "2.4.3-p2",
			advisory:       cosmicSting,
			want:           true,
		},
		{
			name:           "patch numbers are compared by value",
			currentVersion: "2.4.4-p10",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{">=2.4.4-p1, <2.4.4-p8"},
			},
			want: false,
		},
		{
			name:           "patch written as pl",
			currentVersion: "3.1.7",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"<3.1.7-PL1"},
			},
			want: true,
		},
		{
			name:           "patch of a fixed release",
			currentVersion: "4.0.6-p1",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{">=4.0.0, <4.0.6"},
			},
			want: false,
		},

		// The stabilities are ordered as dev, alpha, beta, RC and the release.
		{
			name:           "RC follows alpha",
			currentVersion: "2.0.0-RC1",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{">=2.0.0-alpha1, <2.2.23"},
			},
			want: true,
		},
		{
			name:           "beta precedes RC",
			currentVersion: "3.0.0-beta.1",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{">=3.0.0-RC1, <3.9.15"},
			},
			want: false,
		},
		{
			name:           "RC precedes the release",
			currentVersion: "3.2.0-RC",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"<3.2.0-alpha"},
			},
			want: false,
		},
		{
			name:           "pre-release of the fixed version",
			currentVersion: "2.0.0-beta1",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"<2.0.0"},
			},
			want: true,
		},
		{
			name:           "dev precedes alpha",
			currentVersion: "1.0.0-dev",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{">=1.0.0-alpha1"},
			},
			want: false,
		},
		{
			name:           "stability numbers are compared by value",
			currentVersion: "v4.0.0-rc2",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{">=4.0.0-rc10, <=4.0.0"},
			},
			want: false,
		},
		{
			name:           "stability without a number precedes the numbered one",
			currentVersion: "4.0.0-RC",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"<4.0.0-RC.2"},
			},
			want: true,
		},

		// A stability is written in several ways.
		{
			name:           "stability case",
			currentVersion: "2.8.0-RC1",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{">=2.8.0-rc1, <2.8.2"},
			},
			want: true,
		},
		{
			name:           "stability number after a dot",
			currentVersion: "4.0.0-rc.2",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{">=4.0.0-rc2, <4.2.4"},
			},
			want: true,
		},
		{
			name:           "stability after a dot",
			currentVersion: "5.70.0",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{">=6.0.0.alpha.1, <6.7.2"},
			},
			want: false,
		},
		{
			name:           "stability after an underscore",
			currentVersion: "v7.0.0_rc1",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"<=7.1.0-rc4"},
			},
			want: true,
		},
		{
			name:           "short stability names",
			currentVersion: "1.0.0b2",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{">1.0.0a3, <1.0.0-beta3"},
			},
			want: true,
		},

		{
			name:           "date based version",
			currentVersion: "2021-10-01",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{">=2021.09.15, <2021.10.02"},
			},
			want: true,
		},

		// What Composer cannot read is compared as a SemVer-like version.
		{
			name:           "range Composer cannot read",
			currentVersion: "5.1.0",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"<6.0.0-GM"},
			},
			want: true,
		},
		{
			name:           "version Composer cannot read",
			currentVersion: "1.2.3.4.5",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"<1.2.4"},
			},
			want: true,
		},
		{
			name:           "branch",
			currentVersion: "dev-main",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"<1.2.4"},
			},
			want: false,
		},
		{
			name:           "numeric branch",
			currentVersion: "2.0.x-dev",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{">=2.0.0, <2.0.5"},
			},
			want: false,
		},
		{
			name:           "invalid version",
			currentVersion: "1.2..4",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"<1.2.4"},
			},
			want: false,
		},
		{
			name:           "improper constraint",
			currentVersion: "1.2.3",
			advisory: dbTypes.Advisory{
				VulnerableVersions: []string{"*"},
			},
			want: false,
		},
		{
			name:           "empty patched version",
			currentVersion: "1.2.3",
			advisory: dbTypes.Advisory{
				PatchedVersions: []string{""},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := composer.Comparer{}.IsVulnerable(tt.currentVersion, tt.advisory)
			assert.Equal(t, tt.want, got)
		})
	}
}
