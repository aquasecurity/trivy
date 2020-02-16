package library

import (
	"path/filepath"
	"time"

	"github.com/google/wire"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/knqyf263/go-version"

	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/types"
)

var SuperSet = wire.NewSet(
	wire.Struct(new(DriverFactory)),
	wire.Bind(new(Factory), new(DriverFactory)),
	NewDetector,
	wire.Bind(new(Operation), new(Detector)),
)

type Operation interface {
	Detect(string, string, time.Time, []ptypes.Library) ([]types.DetectedVulnerability, error)
}

type Detector struct {
	driverFactory Factory
}

func NewDetector(factory Factory) Detector {
	return Detector{driverFactory: factory}
}

func (d Detector) Detect(_ string, filePath string, _ time.Time, pkgs []ptypes.Library) ([]types.DetectedVulnerability, error) {
	log.Logger.Debugf("Detecting library vulnerabilities, path: %s", filePath)
	driver := d.driverFactory.NewDriver(filepath.Base(filePath))
	if driver == nil {
		return nil, xerrors.New("unknown file type")
	}

	vulns, err := detect(driver, pkgs)
	if err != nil {
		return nil, xerrors.Errorf("failed to scan %s vulnerabilities: %w", driver.Type(), err)
	}

	return vulns, nil
}

func detect(driver Driver, libs []ptypes.Library) ([]types.DetectedVulnerability, error) {
	log.Logger.Infof("Detecting %s vulnerabilities...", driver.Type())
	var vulnerabilities []types.DetectedVulnerability
	for _, lib := range libs {
		v, err := version.NewVersion(lib.Version)
		if err != nil {
			log.Logger.Debugf("invalid version, library: %s, version: %s, error: %s\n",
				lib.Name, lib.Version, err)
			continue
		}

		vulns, err := driver.Detect(lib.Name, v)
		if err != nil {
			return nil, xerrors.Errorf("failed to detect %s vulnerabilities: %w", driver.Type(), err)
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return vulnerabilities, nil
}
