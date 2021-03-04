package suse

import (
	"testing"
	"time"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"

	susecvrf "github.com/aquasecurity/trivy-db/pkg/vulnsrc/suse-cvrf"

	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
)

type MockSuseConfig struct {
	update func(string) error
	get    func(string, string) ([]dbTypes.Advisory, error)
}

func (msc MockSuseConfig) Update(a string) error {
	if msc.update != nil {
		return msc.update(a)
	}
	return nil
}

func (msc MockSuseConfig) Get(a string, b string) ([]dbTypes.Advisory, error) {
	if msc.get != nil {
		return msc.get(a, b)
	}
	return []dbTypes.Advisory{}, nil
}

func TestScanner_IsSupportedVersion(t *testing.T) {
	vectors := map[string]struct {
		clock        clock.Clock
		osFamily     string
		osVersion    string
		distribution susecvrf.Distribution
		expected     bool
	}{
		"opensuse.leap42.3": {
			clock:        clocktesting.NewFakeClock(time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC)),
			osFamily:     "opensuse.leap",
			osVersion:    "42.3",
			distribution: susecvrf.OpenSUSE,
			expected:     true,
		},
		"opensuse.leap15": {
			clock:        clocktesting.NewFakeClock(time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC)),
			osFamily:     "opensuse.leap",
			osVersion:    "15.0",
			distribution: susecvrf.OpenSUSE,
			expected:     true,
		},
		"opensuse.leap15.1": {
			clock:        clocktesting.NewFakeClock(time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC)),
			osFamily:     "opensuse.leap",
			osVersion:    "15.1",
			distribution: susecvrf.OpenSUSE,
			expected:     true,
		},
		"opensuse.leap15.1-sametime": {
			clock:        clocktesting.NewFakeClock(time.Date(2020, 11, 30, 23, 59, 59, 0, time.UTC)),
			osFamily:     "opensuse.leap",
			osVersion:    "15.1",
			distribution: susecvrf.OpenSUSE,
			expected:     false,
		},
		"sles12.3": {
			clock:        clocktesting.NewFakeClock(time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC)),
			osFamily:     "suse linux enterprise server",
			osVersion:    "12.3",
			distribution: susecvrf.SUSEEnterpriseLinux,
			expected:     false,
		},
		"sles15": {
			clock:        clocktesting.NewFakeClock(time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC)),
			osFamily:     "suse linux enterprise server",
			osVersion:    "15",
			distribution: susecvrf.SUSEEnterpriseLinux,
			expected:     true,
		},
		"unknown": {
			clock:        clocktesting.NewFakeClock(time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC)),
			osFamily:     "oracle",
			osVersion:    "unknown",
			distribution: susecvrf.SUSEEnterpriseLinux,
			expected:     false,
		},
	}

	for testName, v := range vectors {
		s := &Scanner{
			vs:    susecvrf.NewVulnSrc(v.distribution),
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
			vs: MockSuseConfig{
				get: func(s string, s2 string) (advisories []dbTypes.Advisory, err error) {
					return []dbTypes.Advisory{
						{
							VulnerabilityID: "suse-123",
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
				Layer: ftypes.Layer{
					DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
				},
			},
		})
		assert.NoError(t, err)
		assert.Equal(t, []types.DetectedVulnerability{
			{
				VulnerabilityID:  "suse-123",
				PkgName:          "testpkg",
				InstalledVersion: "2.1.0-hotfix",
				FixedVersion:     "3.0.0",
				Layer: ftypes.Layer{
					DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
				},
			},
		}, vuls)
	})

	// TODO: Add unhappy paths
}
