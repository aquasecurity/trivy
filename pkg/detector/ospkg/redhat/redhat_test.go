package redhat

import (
	"testing"
	"time"

	ftypes "github.com/aquasecurity/fanal/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanner_Detect(t *testing.T) {
	type args struct {
		osVer string
		pkgs  []ftypes.Package
	}
	tests := []struct {
		name    string
		args    args
		get     []dbTypes.GetExpectation
		want    []types.DetectedVulnerability
		wantErr bool
	}{
		{
			name: "happy path: src pkg name is different from bin pkg name",
			args: args{
				osVer: "7.6",
				pkgs: []ftypes.Package{
					{
						Name:       "vim-minimal",
						Version:    "7.4.160",
						Release:    "5.el7",
						Epoch:      2,
						Arch:       "x86_64",
						SrcName:    "vim",
						SrcVersion: "7.4.160",
						SrcRelease: "5.el7",
						SrcEpoch:   2,
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
			},
			get: []dbTypes.GetExpectation{
				{
					Args: dbTypes.GetArgs{
						Release: "7",
						PkgName: "vim",
					},
					Returns: dbTypes.GetReturns{
						Advisories: []dbTypes.Advisory{
							{
								VulnerabilityID: "CVE-2017-5953",
								FixedVersion:    "",
							},
							{
								VulnerabilityID: "CVE-2017-6350",
								FixedVersion:    "",
							},
						},
					},
				},
				{
					Args: dbTypes.GetArgs{
						Release: "7",
						PkgName: "vim-minimal",
					},
					Returns: dbTypes.GetReturns{
						Advisories: []dbTypes.Advisory{
							{
								VulnerabilityID: "CVE-2019-12735",
								FixedVersion:    "2:7.4.160-6.el7_6",
							},
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2017-5953",
					PkgName:          "vim-minimal",
					InstalledVersion: "2:7.4.160-5.el7",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
				},
				{
					VulnerabilityID:  "CVE-2017-6350",
					PkgName:          "vim-minimal",
					InstalledVersion: "2:7.4.160-5.el7",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
				},
				{
					VulnerabilityID:  "CVE-2019-12735",
					PkgName:          "vim-minimal",
					InstalledVersion: "2:7.4.160-5.el7",
					FixedVersion:     "2:7.4.160-6.el7_6",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
				},
			},
		},
		{
			name: "happy path: src pkg name is the same as bin pkg name",
			args: args{
				osVer: "6.5",
				pkgs: []ftypes.Package{
					{
						Name:       "nss",
						Version:    "3.36.0",
						Release:    "7.1.el7_6",
						Epoch:      0,
						Arch:       "x86_64",
						SrcName:    "nss",
						SrcVersion: "3.36.0",
						SrcRelease: "7.4.160",
						SrcEpoch:   0,
					},
				},
			},
			get: []dbTypes.GetExpectation{
				{
					Args: dbTypes.GetArgs{
						Release: "6",
						PkgName: "nss",
					},
					Returns: dbTypes.GetReturns{
						Advisories: []dbTypes.Advisory{
							{
								VulnerabilityID: "CVE-2015-2808",
								FixedVersion:    "",
							},
							{
								VulnerabilityID: "CVE-2016-2183",
								FixedVersion:    "",
							},
							{
								VulnerabilityID: "CVE-2018-12404",
								FixedVersion:    "3.44.0-4.el7",
							},
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2015-2808",
					PkgName:          "nss",
					InstalledVersion: "3.36.0-7.1.el7_6",
				},
				{
					VulnerabilityID:  "CVE-2016-2183",
					PkgName:          "nss",
					InstalledVersion: "3.36.0-7.1.el7_6",
				},
				{
					VulnerabilityID:  "CVE-2018-12404",
					PkgName:          "nss",
					InstalledVersion: "3.36.0-7.1.el7_6",
					FixedVersion:     "3.44.0-4.el7",
				},
			},
		},
		{
			name: "happy path: modular packages",
			args: args{
				osVer: "8.3",
				pkgs: []ftypes.Package{
					{
						Name:            "php",
						Version:         "7.2.24",
						Release:         "1.module_el8.2.0+313+b04d0a66",
						Arch:            "x86_64",
						Epoch:           0,
						SrcName:         "php",
						SrcVersion:      "7.2.24",
						SrcRelease:      "1.module_el8.2.0+313+b04d0a66",
						SrcEpoch:        0,
						Modularitylabel: "php:7.2:8020020200507003613:2c7ca891",
						Layer: ftypes.Layer{
							DiffID: "sha256:3e968ecc016e1b9aa19023798229bf2d25c813d1bf092533f38b056aff820524",
						},
					},
				},
			},
			get: []dbTypes.GetExpectation{
				{
					Args: dbTypes.GetArgs{
						Release: "8",
						PkgName: "php:7.2::php",
					},
					Returns: dbTypes.GetReturns{
						Advisories: []dbTypes.Advisory{
							{
								VulnerabilityID: "CVE-2019-11043",
								FixedVersion:    "7.3.5-5.module+el8.1.0+4560+e0eee7d6",
							},
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2019-11043",
					PkgName:          "php",
					InstalledVersion: "7.2.24-1.module_el8.2.0+313+b04d0a66",
					FixedVersion:     "7.3.5-5.module+el8.1.0+4560+e0eee7d6",
					Layer: ftypes.Layer{
						DiffID: "sha256:3e968ecc016e1b9aa19023798229bf2d25c813d1bf092533f38b056aff820524",
					},
				},
			},
		},
		{
			name: "happy path: packages from remi repository are skipped",
			args: args{
				osVer: "7.6",
				pkgs: []ftypes.Package{
					{
						Name:       "php",
						Version:    "7.3.23",
						Release:    "1.el7.remi",
						Arch:       "x86_64",
						Epoch:      0,
						SrcName:    "php",
						SrcVersion: "7.3.23",
						SrcRelease: "1.el7.remi",
						SrcEpoch:   0,
						Layer: ftypes.Layer{
							DiffID: "sha256:c27b3cf4d516baf5932d5df3a573c6a571ddace3ee2a577492292d2e849c112b",
						},
					},
				},
			},
			get: []dbTypes.GetExpectation{
				{
					Args: dbTypes.GetArgs{
						Release: "7",
						PkgName: "php",
					},
					Returns: dbTypes.GetReturns{
						Advisories: []dbTypes.Advisory{
							{
								VulnerabilityID: "CVE-2011-4718",
								FixedVersion:    "",
							},
						},
					},
				},
			},
			want: []types.DetectedVulnerability(nil),
		},
		{
			name: "sad path: Get returns an error",
			args: args{
				osVer: "5",
				pkgs: []ftypes.Package{
					{
						Name:       "nss",
						Version:    "3.36.0",
						Release:    "7.1.el7_6",
						Epoch:      0,
						Arch:       "x86_64",
						SrcName:    "nss",
						SrcVersion: "3.36.0",
						SrcRelease: "7.4.160",
						SrcEpoch:   0,
					},
				},
			},
			get: []dbTypes.GetExpectation{
				{
					Args: dbTypes.GetArgs{
						Release: "5",
						PkgName: "nss",
					},
					Returns: dbTypes.GetReturns{
						Err: xerrors.New("error"),
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockVs := new(dbTypes.MockVulnSrc)
			mockVs.ApplyGetExpectations(tt.get)
			s := &Scanner{
				vs: mockVs,
			}
			got, err := s.Detect(tt.args.osVer, tt.args.pkgs)
			require.Equal(t, tt.wantErr, err != nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestScanner_IsSupportedVersion(t *testing.T) {
	vectors := map[string]struct {
		now       time.Time
		osFamily  string
		osVersion string
		expected  bool
	}{
		"centos5": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "centos",
			osVersion: "5.0",
			expected:  false,
		},
		"centos6": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "centos",
			osVersion: "6.7",
			expected:  true,
		},
		"centos6 (eol ends)": {
			now:       time.Date(2020, 12, 1, 0, 0, 0, 0, time.UTC),
			osFamily:  "centos",
			osVersion: "6.7",
			expected:  false,
		},
		"centos7": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "centos",
			osVersion: "7.5",
			expected:  true,
		},
		"centos8": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "centos",
			osVersion: "8.0",
			expected:  true,
		},
		"centos8 (eol ends)": {
			now:       time.Date(2022, 12, 1, 0, 0, 0, 0, time.UTC),
			osFamily:  "centos",
			osVersion: "8.0",
			expected:  false,
		},
		"two dots": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "centos",
			osVersion: "8.0.1",
			expected:  true,
		},
		"redhat5": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "redhat",
			osVersion: "5.0",
			expected:  true,
		},
		"redhat6": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "redhat",
			osVersion: "6.7",
			expected:  true,
		},
		"redhat6 (eol ends)": {
			now:       time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC),
			osFamily:  "redhat",
			osVersion: "6.7",
			expected:  false,
		},
		"redhat7": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "redhat",
			osVersion: "7.5",
			expected:  true,
		},
		"redhat8": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "redhat",
			osVersion: "8.0",
			expected:  true,
		},
		"no dot": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "redhat",
			osVersion: "8",
			expected:  true,
		},
		"debian": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "debian",
			osVersion: "8",
			expected:  false,
		},
	}

	for testName, v := range vectors {
		s := NewScanner()
		t.Run(testName, func(t *testing.T) {
			actual := s.isSupportedVersion(v.now, v.osFamily, v.osVersion)
			if actual != v.expected {
				t.Errorf("[%s] got %v, want %v", testName, actual, v.expected)
			}
		})
	}

}
