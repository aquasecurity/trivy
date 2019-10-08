package amazon

import (
	"testing"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/vulnsrc/vulnerability"
	"github.com/stretchr/testify/assert"
)

type MockAmazonConfig struct {
	update func(string, map[string]struct{}) error
	get    func(string, string) ([]vulnerability.Advisory, error)
}

func (mac MockAmazonConfig) Update(a string, b map[string]struct{}) error {
	if mac.update != nil {
		return mac.update(a, b)
	}
	return nil
}

func (mac MockAmazonConfig) Get(a string, b string) ([]vulnerability.Advisory, error) {
	if mac.get != nil {
		return mac.get(a, b)
	}
	return []vulnerability.Advisory{}, nil
}

func TestScanner_Detect(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		_ = log.InitLogger(true, false)
		s := &Scanner{
			l: log.Logger,
			ac: MockAmazonConfig{
				get: func(s string, s2 string) (advisories []vulnerability.Advisory, e error) {
					return []vulnerability.Advisory{
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
		assert.Equal(t, []vulnerability.DetectedVulnerability{
			{
				VulnerabilityID:  "123",
				PkgName:          "testpkg",
				InstalledVersion: "2.1.0-test-hotfix",
				FixedVersion:     "3.0.0",
			},
		}, vuls)
	})
}
