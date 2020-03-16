package oracle

import (
	"os"
	"testing"
	"time"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"

	oracleoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/oracle-oval"
	"github.com/aquasecurity/trivy/pkg/log"

	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
)

type MockOracleConfig struct {
	update func(string) error
	get    func(string, string) ([]dbTypes.Advisory, error)
}

func (moc MockOracleConfig) Update(a string) error {
	if moc.update != nil {
		return moc.update(a)
	}
	return nil
}

func (moc MockOracleConfig) Get(a string, b string) ([]dbTypes.Advisory, error) {
	if moc.get != nil {
		return moc.get(a, b)
	}
	return []dbTypes.Advisory{}, nil
}

func TestMain(m *testing.M) {
	log.InitLogger(false, false)
	os.Exit(m.Run())
}

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
	t.Run("happy path", func(t *testing.T) {
		s := &Scanner{
			vs: MockOracleConfig{
				get: func(s string, s2 string) (advisories []dbTypes.Advisory, err error) {
					return []dbTypes.Advisory{
						{
							VulnerabilityID: "oracle-123",
							FixedVersion:    "3.0.0",
						},
					}, nil
				},
			},
		}

		vuls, err := s.Detect("3.1.0", []ftypes.Package{
			{
				Name:       "testpkg",
				Version:    "2.1.0",
				Release:    "hotfix",
				SrcRelease: "test-hotfix",
				SrcVersion: "2.1.0",
				LayerID:    "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
			},
			//{
			//	Name: "foopkg",
			//},
		})
		assert.NoError(t, err)
		assert.Equal(t, []types.DetectedVulnerability{
			{
				VulnerabilityID:  "oracle-123",
				PkgName:          "testpkg",
				InstalledVersion: "2.1.0-hotfix",
				FixedVersion:     "3.0.0",
				LayerID:          "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
			},
		}, vuls)
	})

	// TODO: Add unhappy paths
}
