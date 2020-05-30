package bundler

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/log"

	bundlerSrc "github.com/aquasecurity/trivy-db/pkg/vulnsrc/bundler"
	"github.com/knqyf263/go-version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockVulnSrc struct {
	mock.Mock
}

func (_m *MockVulnSrc) Get(pkgName string) ([]bundlerSrc.Advisory, error) {
	ret := _m.Called(pkgName)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return nil, ret.Error(1)
	}
	advisories, ok := ret0.([]bundlerSrc.Advisory)
	if !ok {
		return nil, ret.Error(1)
	}
	return advisories, ret.Error(1)
}

func TestScanner_Detect(t *testing.T) {
	log.InitLogger(false, true)
	t.Run("Issue #108", func(t *testing.T) {
		// https://github.com/aquasecurity/trivy/issues/108
		// Validate that the massaging that happens when parsing the lockfile
		// allows us to better handle the platform metadata
		mockVulnSrc := new(MockVulnSrc)
		mockVulnSrc.On("Get", "ffi").Return(
			[]bundlerSrc.Advisory{
				{
					VulnerabilityID: "NotDetected",
					PatchedVersions: []string{">= 1.9.24"},
				},
				{
					VulnerabilityID: "Detected",
					PatchedVersions: []string{">= 1.9.26"},
				},
			}, nil)
		s := Advisory{
			vs: mockVulnSrc,
		}

		versionStr := "1.9.25-x64-mingw32"
		versionStr = platformReplacer.Replace(versionStr)

		v, _ := version.NewVersion(versionStr)

		vulns, err := s.DetectVulnerabilities("ffi", v)

		assert.Nil(t, err)
		assert.Equal(t, 1, len(vulns))
	})
}
