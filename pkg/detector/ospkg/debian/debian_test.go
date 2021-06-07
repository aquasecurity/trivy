package debian

import (
	"testing"
	"time"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

type MockOvalConfig struct {
	update func(string) error
	get    func(string, string) ([]dbTypes.Advisory, error)
}

func (mdc MockOvalConfig) Update(a string) error {
	if mdc.update != nil {
		return mdc.update(a)
	}
	return nil
}

func (mdc MockOvalConfig) Get(a string, b string) ([]dbTypes.Advisory, error) {
	if mdc.get != nil {
		return mdc.get(a, b)
	}
	return []dbTypes.Advisory{}, nil
}

type MockDebianConfig struct {
	update func(string) error
	get    func(string, string) ([]dbTypes.Advisory, error)
}

func (mdc MockDebianConfig) Update(a string) error {
	if mdc.update != nil {
		return mdc.update(a)
	}
	return nil
}

func (mdc MockDebianConfig) Get(a string, b string) ([]dbTypes.Advisory, error) {
	if mdc.get != nil {
		return mdc.get(a, b)
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
		"debian7": {
			now:       time.Date(2019, 3, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "debian",
			osVersion: "7",
			expected:  false,
		},
		"debian8": {
			now:       time.Date(2019, 3, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "debian",
			osVersion: "8.11",
			expected:  true,
		},
		"debian8 eol ends": {
			now:       time.Date(2020, 7, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "debian",
			osVersion: "8.0",
			expected:  false,
		},
		"debian9": {
			now:       time.Date(2020, 7, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "debian",
			osVersion: "9",
			expected:  true,
		},
		"debian9 eol ends": {
			now:       time.Date(2022, 7, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "debian",
			osVersion: "9",
			expected:  false,
		},
		"debian10": {
			now:       time.Date(2020, 7, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "debian",
			osVersion: "10",
			expected:  true,
		},
		"debian10 eol ends": {
			now:       time.Date(2024, 7, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "debian",
			osVersion: "10",
			expected:  false,
		},
		"unknown": {
			now:       time.Date(2020, 7, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "debian",
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
			vs: MockDebianConfig{
				get: func(s string, s2 string) (advisories []dbTypes.Advisory, err error) {
					return []dbTypes.Advisory{
						{
							VulnerabilityID: "debian-123",
						},
					}, nil
				},
			},
			ovalVs: MockOvalConfig{
				get: func(s string, s2 string) (advisories []dbTypes.Advisory, e error) {
					return []dbTypes.Advisory{
						{
							VulnerabilityID: "oval-123",
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
			{
				Name: "foopkg",
			},
		})
		assert.NoError(t, err)
		assert.Equal(t, []types.DetectedVulnerability{
			{
				VulnerabilityID:  "oval-123",
				PkgName:          "testpkg",
				InstalledVersion: "2.1.0-test-hotfix",
				FixedVersion:     "3.0.0",
				Layer: ftypes.Layer{
					DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
				},
			},
			{
				VulnerabilityID:  "debian-123",
				PkgName:          "testpkg",
				InstalledVersion: "2.1.0-test-hotfix",
				Layer: ftypes.Layer{
					DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
				},
			},
		}, vuls)
	})

	// TODO: Add unhappy paths
}
