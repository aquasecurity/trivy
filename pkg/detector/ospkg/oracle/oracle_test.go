package oracle

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	oracleoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/oracle-oval"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/dbtest"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanner_IsSupportedVersion(t *testing.T) {
	vectors := map[string]struct {
		clock     clock.Clock
		osFamily  string
		osVersion string
		expected  bool
	}{
		"oracle3": {
			clock:     clocktesting.NewFakeClock(time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC)),
			osFamily:  "oracle",
			osVersion: "3",
			expected:  false,
		},
		"oracle4": {
			clock:     clocktesting.NewFakeClock(time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC)),
			osFamily:  "oracle",
			osVersion: "4",
			expected:  false,
		},
		"oracle5": {
			clock:     clocktesting.NewFakeClock(time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC)),
			osFamily:  "oracle",
			osVersion: "5",
			expected:  false,
		},
		"oracle6": {
			clock:     clocktesting.NewFakeClock(time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC)),
			osFamily:  "oracle",
			osVersion: "6",
			expected:  true,
		},
		"oracle7": {
			clock:     clocktesting.NewFakeClock(time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC)),
			osFamily:  "oracle",
			osVersion: "7",
			expected:  true,
		},
		"oracle7.6": {
			clock:     clocktesting.NewFakeClock(time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC)),
			osFamily:  "oracle",
			osVersion: "7.6",
			expected:  true,
		},
		"oracle8": {
			clock:     clocktesting.NewFakeClock(time.Date(2029, 7, 18, 23, 59, 58, 59, time.UTC)),
			osFamily:  "oracle",
			osVersion: "8",
			expected:  true,
		},
		"oracle8-same-time": {
			clock:     clocktesting.NewFakeClock(time.Date(2029, 7, 18, 23, 59, 59, 0, time.UTC)),
			osFamily:  "oracle",
			osVersion: "8",
			expected:  false,
		},
		"unknown": {
			clock:     clocktesting.NewFakeClock(time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC)),
			osFamily:  "oracle",
			osVersion: "unknown",
			expected:  false,
		},
	}

	for testName, v := range vectors {
		s := &Scanner{
			vs:    oracleoval.NewVulnSrc(),
			clock: v.clock,
		}
		t.Run(testName, func(t *testing.T) {
			actual := s.IsSupportedVersion(v.osFamily, v.osVersion)
			if actual != v.expected {
				t.Errorf("[%s] got %v, want %v", testName, actual, v.expected)
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
			name:     "detected",
			fixtures: []string{"testdata/fixtures/oracle7.yaml", "testdata/fixtures/data-source.yaml"},
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
					VendorIDs:        []string{"ELSA-2020-5002"},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
			},
		},
		{
			name:     "without ksplice",
			fixtures: []string{"testdata/fixtures/oracle7.yaml", "testdata/fixtures/data-source.yaml"},
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
			name:     "with ksplice",
			fixtures: []string{"testdata/fixtures/oracle7.yaml", "testdata/fixtures/data-source.yaml"},
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
					VendorIDs:        []string{"ELSA-2017-3582"},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
			},
		},
		{
			name:     "ksplice2",
			fixtures: []string{"testdata/fixtures/oracle7.yaml", "testdata/fixtures/data-source.yaml"},
			args: args{
				osVer: "7",
				pkgs: []ftypes.Package{
					{
						Name:       "glibcx",
						Epoch:      0,
						Version:    "0.1",
						Release:    "123.ksplice1.el7_3.4",
						Arch:       "x86_64",
						SrcEpoch:   0,
						SrcName:    "glibc",
						SrcVersion: "0.1",
						SrcRelease: "123.ksplice1.el7_3.4",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2001-10001",
					PkgName:          "glibcx",
					InstalledVersion: "0.1-123.ksplice1.el7_3.4",
					FixedVersion:     "0.1-123.ksplice2.el7_3.4",
					VendorIDs:        []string{"ELSA-2001-1001"},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
			},
		},
		{
			name:     "malformed",
			fixtures: []string{"testdata/fixtures/invalid-type.yaml", "testdata/fixtures/data-source.yaml"},
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
			wantErr: "failed to unmarshal advisory JSON",
		},
		{
			name:     "unpatched without fips",
			fixtures: []string{"testdata/fixtures/oracle7.yaml", "testdata/fixtures/data-source.yaml"},
			args: args{
				osVer: "7",
				pkgs: []ftypes.Package{
					{
						Name:       "gnutls",
						Version:    "3.6.3",
						Release:    "1.el8",
						Arch:       "x86_64",
						SrcName:    "gnutls",
						SrcVersion: "3.6.3",
						SrcRelease: "1.el8",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2021-20231",
					PkgName:          "gnutls",
					InstalledVersion: "3.6.3-1.el8",
					FixedVersion:     "3.6.16-4.el8",
					VendorIDs:        []string{"ELSA-2021-4451"},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
				{
					VulnerabilityID:  "CVE-2021-20232",
					PkgName:          "gnutls",
					InstalledVersion: "3.6.3-1.el8",
					FixedVersion:     "3.6.16-4.el8",
					VendorIDs:        []string{"ELSA-2021-4451"},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
				{
					VulnerabilityID:  "CVE-2021-3580",
					PkgName:          "gnutls",
					InstalledVersion: "3.6.3-1.el8",
					FixedVersion:     "3.6.16-4.el8",
					VendorIDs:        []string{"ELSA-2021-4451"},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
			},
		},
		{
			name:     "patched without fips",
			fixtures: []string{"testdata/fixtures/oracle7.yaml", "testdata/fixtures/data-source.yaml"},
			args: args{
				osVer: "7",
				pkgs: []ftypes.Package{
					{
						Name:       "gnutls",
						Version:    "3.6.16",
						Release:    "4.el8",
						Arch:       "x86_64",
						SrcName:    "gnutls",
						SrcVersion: "3.6.16",
						SrcRelease: "4.el8",
					},
				},
			},
			want: nil,
		},
		{
			name:     "unpatched with fips",
			fixtures: []string{"testdata/fixtures/oracle7.yaml", "testdata/fixtures/data-source.yaml"},
			args: args{
				osVer: "7",
				pkgs: []ftypes.Package{
					{
						Name:       "gnutls",
						Epoch:      10,
						Version:    "3.6.16",
						Release:    "4.el8_fips",
						Arch:       "x86_64",
						SrcEpoch:   10,
						SrcName:    "gnutls",
						SrcVersion: "3.6.16_fips",
						SrcRelease: "4.el8",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2021-20231",
					PkgName:          "gnutls",
					InstalledVersion: "10:3.6.16-4.el8_fips",
					FixedVersion:     "10:3.6.16-4.0.1.el8_fips",
					VendorIDs:        []string{"ELSA-2022-9221"},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
				{
					VulnerabilityID:  "CVE-2021-20232",
					PkgName:          "gnutls",
					InstalledVersion: "10:3.6.16-4.el8_fips",
					FixedVersion:     "10:3.6.16-4.0.1.el8_fips",
					VendorIDs:        []string{"ELSA-2022-9221"},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
				{
					VulnerabilityID:  "CVE-2021-3580",
					PkgName:          "gnutls",
					InstalledVersion: "10:3.6.16-4.el8_fips",
					FixedVersion:     "10:3.6.16-4.0.1.el8_fips",
					VendorIDs:        []string{"ELSA-2022-9221"},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
			},
		},
		{
			name:     "multiple advisories",
			fixtures: []string{"testdata/fixtures/multiple-advisories.yaml", "testdata/fixtures/data-source.yaml"},
			args: args{
				osVer: "7",
				pkgs: []ftypes.Package{
					{
						Name:       "kernel-uek",
						Version:    "5.4.17",
						Release:    "2102.201.1.el8",
						SrcName:    "kernel-uek",
						SrcVersion: "5.4.17",
						SrcRelease: "2102.201.1.el8",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2021-23133",
					PkgName:          "kernel-uek",
					InstalledVersion: "5.4.17-2102.201.1.el8",
					FixedVersion:     "5.4.17-2102.203.5.el8",
					VendorIDs: []string{
						"ELSA-2021-9306",
						"ELSA-2021-9362",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := NewScanner()
			got, err := s.Detect(tt.args.osVer, nil, tt.args.pkgs)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				assert.NoError(t, err)
			}

			assert.ElementsMatch(t, tt.want, got)
		})
	}
}
