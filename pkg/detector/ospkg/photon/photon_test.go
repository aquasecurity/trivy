package photon

import (
	"testing"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

type MockPhotonConfig struct {
	update func(string) error
	get    func(string, string) ([]dbTypes.Advisory, error)
}

func (mpc MockPhotonConfig) Update(a string) error {
	if mpc.update != nil {
		return mpc.update(a)
	}
	return nil
}

func (mpc MockPhotonConfig) Get(a string, b string) ([]dbTypes.Advisory, error) {
	if mpc.get != nil {
		return mpc.get(a, b)
	}
	return []dbTypes.Advisory{}, nil
}

func TestScanner_Detect(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		s := &Scanner{
			vs: MockPhotonConfig{
				get: func(s string, s2 string) (advisories []dbTypes.Advisory, err error) {
					return []dbTypes.Advisory{
						{
							VulnerabilityID: "photon-123",
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
				VulnerabilityID:  "photon-123",
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
