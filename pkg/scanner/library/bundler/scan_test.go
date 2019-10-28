package bundler

import (
	"github.com/knqyf263/go-version"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestScanner_Detect(t *testing.T) {
	t.Run("Issue #108", func(t *testing.T) {
		// https://github.com/aquasecurity/trivy/issues/108
		// Validate that the massaging that happens when parsing the lockfile
		// allows us to better handle the platform metadata
		s := NewScanner()

		s.db = AdvisoryDB{
			"ffi": []Advisory{
				{
					Gem:             "ffi",
					PatchedVersions: []string{">= 1.9.24"},
				},
			},
		}

		versionStr := "1.9.25-x64-mingw32"

		versionStr = platformReplacer.Replace(versionStr)

		v, _ := version.NewVersion(versionStr)

		vulns, err := s.Detect("ffi", v)

		assert.Nil(t, err)

		assert.Equal(t, len(vulns), 0)
	})
}
