package oracle

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/clock"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanner_IsSupportedVersion(t *testing.T) {
	tests := map[string]struct {
		now       time.Time
		osFamily  ftypes.OSType
		osVersion string
		expected  bool
	}{
		"oracle3": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "oracle",
			osVersion: "3",
			expected:  false,
		},
		"oracle4": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "oracle",
			osVersion: "4",
			expected:  false,
		},
		"oracle5": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "oracle",
			osVersion: "5",
			expected:  false,
		},
		"oracle6": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "oracle",
			osVersion: "6",
			expected:  true,
		},
		"oracle7": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "oracle",
			osVersion: "7",
			expected:  true,
		},
		"oracle7.6": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "oracle",
			osVersion: "7.6",
			expected:  true,
		},
		"oracle8": {
			now:       time.Date(2029, 7, 18, 23, 59, 58, 59, time.UTC),
			osFamily:  "oracle",
			osVersion: "8",
			expected:  true,
		},
		"oracle8-same-time": {
			now:       time.Date(2029, 7, 18, 23, 59, 59, 0, time.UTC),
			osFamily:  "oracle",
			osVersion: "8",
			expected:  false,
		},
		"latest": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "oracle",
			osVersion: "latest",
			expected:  true,
		},
	}

	for testName, tt := range tests {
		s := NewScanner()
		t.Run(testName, func(t *testing.T) {
			ctx := clock.With(t.Context(), tt.now)
			actual := s.IsSupportedVersion(ctx, tt.osFamily, tt.osVersion)
			if actual != tt.expected {
				t.Errorf("[%s] got %v, want %v", testName, actual, tt.expected)
			}
		})
	}

}

func TestScanner_Detect(t *testing.T) {
	type args struct {
		osVer string
		pkgs  []ftypes.Package
	}
	tests := []struct {
		name     string
		args     args
		fixtures []string
		want     []types.DetectedVulnerability
		wantErr  string
	}{
		{
			name: "detected",
			fixtures: []string{
				"testdata/fixtures/oracle7.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "7",
				pkgs: []ftypes.Package{
					{
						Name:       "curl",
						Version:    "7.29.0",
						Release:    "59.0.1.el7",
						Arch:       "x86_64",
						SrcName:    "curl",
						SrcVersion: "7.29.0",
						SrcRelease: "59.0.1.el7",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2020-8177",
					PkgName:          "curl",
					InstalledVersion: "7.29.0-59.0.1.el7",
					FixedVersion:     "7.29.0-59.0.1.el7_9.1",
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
			},
		},
		{
			name: "different fixed versions for different arches",
			fixtures: []string{
				"testdata/fixtures/oracle7.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "7",
				pkgs: []ftypes.Package{
					{
						Name:       "rsyslog",
						Version:    "8.24.0",
						Release:    "57.0.0.el7",
						Arch:       "x86_64",
						SrcName:    "rsyslog",
						SrcVersion: "8.24.0",
						SrcRelease: "57.0.0.el7",
					},
					{
						Name:       "rsyslog",
						Version:    "8.24.0",
						Release:    "57.0.0.el7",
						Arch:       "aarch64",
						SrcName:    "rsyslog",
						SrcVersion: "8.24.0",
						SrcRelease: "57.0.0.el7",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2022-24903",
					PkgName:          "rsyslog",
					InstalledVersion: "8.24.0-57.0.0.el7",
					FixedVersion:     "8.24.0-57.0.1.el7_9.3",
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
				{
					VulnerabilityID:  "CVE-2022-24903",
					PkgName:          "rsyslog",
					InstalledVersion: "8.24.0-57.0.0.el7",
					FixedVersion:     "8.24.0-57.0.4.el7_9.3",
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
			},
		},
		{
			name: "without ksplice",
			fixtures: []string{
				"testdata/fixtures/oracle7.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "7",
				pkgs: []ftypes.Package{
					{
						Name:       "glibc",
						Version:    "2.17",
						Release:    "317.0.1.el7",
						Arch:       "x86_64",
						SrcName:    "glibc",
						SrcVersion: "2.17",
						SrcRelease: "317.0.1.el7",
					},
				},
			},
			want: nil,
		},
		{
			name: "the installed version has ksplice2",
			fixtures: []string{
				"testdata/fixtures/oracle7.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "7",
				pkgs: []ftypes.Package{
					{
						Name:       "glibc",
						Epoch:      2,
						Version:    "2.28",
						Release:    "151.0.1.ksplice2.el8",
						Arch:       "x86_64",
						SrcEpoch:   2,
						SrcName:    "glibc",
						SrcVersion: "2.28",
						SrcRelease: "151.0.1.ksplice2.el8",
					},
				},
			},
			want: nil,
		},
		{
			name: "with ksplice",
			fixtures: []string{
				"testdata/fixtures/oracle7.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "7",
				pkgs: []ftypes.Package{
					{
						Name:       "glibc",
						Epoch:      2,
						Version:    "2.17",
						Release:    "156.ksplice1.el7",
						Arch:       "x86_64",
						SrcEpoch:   2,
						SrcName:    "glibc",
						SrcVersion: "2.17",
						SrcRelease: "156.ksplice1.el7",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2017-1000364",
					PkgName:          "glibc",
					InstalledVersion: "2:2.17-156.ksplice1.el7",
					FixedVersion:     "2:2.17-157.ksplice1.el7_3.4",
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
			},
		},
		{
			name: "with fips",
			fixtures: []string{
				"testdata/fixtures/oracle7.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "7",
				pkgs: []ftypes.Package{
					{
						Name:       "gnutls",
						Epoch:      10,
						Version:    "3.6.15",
						Release:    "4.0.1.el8_fips",
						Arch:       "x86_64",
						SrcEpoch:   2,
						SrcName:    "gnutls",
						SrcVersion: "3.6.15",
						SrcRelease: "4.0.1.el8_fips",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2021-20232",
					PkgName:          "gnutls",
					InstalledVersion: "10:3.6.15-4.0.1.el8_fips",
					FixedVersion:     "10:3.6.16-4.0.1.el8_fips",
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
			},
		},
		{
			name: "malformed",
			fixtures: []string{
				"testdata/fixtures/invalid-type.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "7",
				pkgs: []ftypes.Package{
					{
						Name:       "curl",
						Version:    "7.29.0",
						Release:    "59.0.1.el7",
						Arch:       "x86_64",
						SrcName:    "curl",
						SrcVersion: "7.29.0",
						SrcRelease: "59.0.1.el7",
					},
				},
			},
			wantErr: "failed to get Oracle Linux advisory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := NewScanner()
			got, err := s.Detect(nil, tt.args.osVer, nil, tt.args.pkgs)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.want, got)
		})
	}
}
