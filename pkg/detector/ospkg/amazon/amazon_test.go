package amazon

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

type MockAmazonConfig struct {
	update func(string) error
	get    func(string, string) ([]dbTypes.Advisory, error)
}

func (mac MockAmazonConfig) Update(a string) error {
	if mac.update != nil {
		return mac.update(a)
	}
	return nil
}

func (mac MockAmazonConfig) Get(a string, b string) ([]dbTypes.Advisory, error) {
	if mac.get != nil {
		return mac.get(a, b)
	}
	return []dbTypes.Advisory{}, nil
}

func TestScanner_Detect(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		zc, recorder := observer.New(zapcore.DebugLevel)
		log.Logger = zap.New(zc).Sugar()
		s := &Scanner{
			l: log.Logger,
			ac: MockAmazonConfig{
				get: func(s string, s2 string) (advisories []dbTypes.Advisory, e error) {
					return []dbTypes.Advisory{
						{
							VulnerabilityID: "123",
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
				VulnerabilityID:  "123",
				PkgName:          "testpkg",
				InstalledVersion: "2.1.0-hotfix",
				FixedVersion:     "3.0.0",
				Layer: ftypes.Layer{
					DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
				},
			},
		}, vuls)

		loggedMessages := getAllLoggedLogs(recorder)
		assert.Contains(t, loggedMessages, "amazon: os version: 1")
		assert.Contains(t, loggedMessages, "amazon: the number of packages: 2")
	})

	t.Run("get vulnerabilities fails to fetch", func(t *testing.T) {
		s := &Scanner{
			l: log.Logger,
			ac: MockAmazonConfig{
				get: func(s string, s2 string) (advisories []dbTypes.Advisory, e error) {
					return nil, errors.New("failed to fetch advisories")
				},
			},
		}
		vuls, err := s.Detect("foo", []ftypes.Package{
			{
				Name: "testpkg",
			},
		})
		assert.Equal(t, "failed to get amazon advisories: failed to fetch advisories", err.Error())
		assert.Empty(t, vuls)
	})

	t.Run("invalid installed package version", func(t *testing.T) {
		zc, recorder := observer.New(zapcore.DebugLevel)
		log.Logger = zap.New(zc).Sugar()
		s := &Scanner{
			l: log.Logger,
			ac: MockAmazonConfig{
				get: func(s string, s2 string) (advisories []dbTypes.Advisory, e error) {
					return []dbTypes.Advisory{
						{
							VulnerabilityID: "123",
							FixedVersion:    "3.0.0",
						},
					}, nil
				},
			},
		}

		vuls, err := s.Detect("3.1.0", []ftypes.Package{
			{
				Name:    "testpkg",
				Version: "badsourceversion",
			},
		})
		assert.NoError(t, err)
		assert.Equal(t, []types.DetectedVulnerability(nil), vuls)
		loggedMessages := getAllLoggedLogs(recorder)
		assert.Contains(t, loggedMessages, "failed to parse Amazon Linux installed package version: upstream_version must start with digit")
	})

	t.Run("invalid fixed package version", func(t *testing.T) {
		zc, recorder := observer.New(zapcore.DebugLevel)
		log.Logger = zap.New(zc).Sugar()
		s := &Scanner{
			l: log.Logger,
			ac: MockAmazonConfig{
				get: func(s string, s2 string) (advisories []dbTypes.Advisory, e error) {
					return []dbTypes.Advisory{
						{
							VulnerabilityID: "123",
							FixedVersion:    "thisisbadversioning",
						},
					}, nil
				},
			},
		}

		vuls, err := s.Detect("3.1.0", []ftypes.Package{
			{
				Name:    "testpkg",
				Version: "3.1.0",
			},
		})
		assert.NoError(t, err)
		assert.Equal(t, []types.DetectedVulnerability(nil), vuls)
		loggedMessages := getAllLoggedLogs(recorder)
		assert.Contains(t, loggedMessages, "failed to parse Amazon Linux package version: upstream_version must start with digit")
	})

}

func getAllLoggedLogs(recorder *observer.ObservedLogs) []string {
	allLogs := recorder.AllUntimed()
	var loggedMessages []string
	for _, l := range allLogs {
		loggedMessages = append(loggedMessages, l.Message)
	}
	return loggedMessages
}

func TestScanner_IsSupportedVersion(t *testing.T) {
	vectors := map[string]struct {
		now       time.Time
		osFamily  string
		osVersion string
		expected  bool
	}{
		"1": {
			now:       time.Date(2022, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "amazon",
			osVersion: "1",
			expected:  true,
		},
		"1 (eol ends)": {
			now:       time.Date(2024, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "amazon",
			osVersion: "1",
			expected:  false,
		},
		"2": {
			now:       time.Date(2020, 12, 1, 0, 0, 0, 0, time.UTC),
			osFamily:  "amazon",
			osVersion: "2",
			expected:  true,
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
