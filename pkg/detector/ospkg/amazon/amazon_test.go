package amazon

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/aquasecurity/fanal/analyzer"
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

		vuls, err := s.Detect("3.1.0", []analyzer.Package{
			{
				Name:       "testpkg",
				Version:    "2.1.0",
				Release:    "hotfix",
				SrcRelease: "test-hotfix",
				SrcVersion: "2.1.0",
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
			},
		}, vuls)

		loggedMessages := getAllLoggedLogs(recorder)
		assert.Contains(t, loggedMessages, "amazon: os version: 1")
		assert.Contains(t, loggedMessages, "amazon: the number of packages: 2")
	})

	t.Run("get vulnerabilities fails to fetch", func(t *testing.T) {
		_ = log.InitLogger(true, false)
		s := &Scanner{
			l: log.Logger,
			ac: MockAmazonConfig{
				get: func(s string, s2 string) (advisories []dbTypes.Advisory, e error) {
					return nil, errors.New("failed to fetch advisories")
				},
			},
		}
		vuls, err := s.Detect("foo", []analyzer.Package{
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

		vuls, err := s.Detect("3.1.0", []analyzer.Package{
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

		vuls, err := s.Detect("3.1.0", []analyzer.Package{
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
