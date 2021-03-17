package ubuntu

import (
	"testing"
	"time"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
)

type MockUbuntuConfig struct {
	update func(string) error
	get    func(string, string) ([]dbTypes.Advisory, error)
}

func (muc MockUbuntuConfig) Update(a string) error {
	if muc.update != nil {
		return muc.update(a)
	}
	return nil
}

func (muc MockUbuntuConfig) Get(a string, b string) ([]dbTypes.Advisory, error) {
	if muc.get != nil {
		return muc.get(a, b)
	}
	return []dbTypes.Advisory{}, nil
}

func TestScanner_IsSupportedVersion(t *testing.T) {
	vectors := map[string]struct {
		now       time.Time
		osFamily  string
		osVersion string
		expected  bool
	}{
		"ubuntu12.04 eol ends": {
			now:       time.Date(2019, 3, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "ubuntu",
			osVersion: "12.04",
			expected:  true,
		},
		"ubuntu12.04": {
			now:       time.Date(2019, 4, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "ubuntu",
			osVersion: "12.04",
			expected:  false,
		},
		"ubuntu12.10": {
			now:       time.Date(2019, 4, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "ubuntu",
			osVersion: "12.10",
			expected:  false,
		},
		"ubuntu18.04": {
			now:       time.Date(2019, 4, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "ubuntu",
			osVersion: "18.04",
			expected:  true,
		},
		"ubuntu19.04": {
			now:       time.Date(2019, 4, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "ubuntu",
			osVersion: "19.04",
			expected:  true,
		},
		"unknown": {
			now:       time.Date(2019, 4, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "ubuntu",
			osVersion: "unknown",
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

func TestScanner_Detect(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		s := &Scanner{
			vs: MockUbuntuConfig{
				get: func(s string, s2 string) (advisories []dbTypes.Advisory, err error) {
					return []dbTypes.Advisory{
						{
							VulnerabilityID: "ubuntu-123",
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
				VulnerabilityID:  "ubuntu-123",
				PkgName:          "testpkg",
				InstalledVersion: "2.1.0-test-hotfix",
				FixedVersion:     "3.0.0",
				Layer: ftypes.Layer{
					DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
				},
			},
		}, vuls)
	})

	// TODO: Add unhappy paths
}
