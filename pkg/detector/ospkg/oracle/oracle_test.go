package oracle

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	oracleoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/oracle-oval"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/dbtest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanner_IsSupportedVersion(t *testing.T) {
	vectors := map[string]struct {
		clock     clock.Clock
		osFamily  ftypes.OSType
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
			wantErr: "failed to unmarshal advisory JSON",
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

			assert.Equal(t, tt.want, got)
		})
	}
}
