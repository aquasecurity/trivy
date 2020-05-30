package library

import (
	"path/filepath"
	"time"

	ftypes "github.com/aquasecurity/fanal/types"

	"github.com/google/wire"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/knqyf263/go-version"

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
	Detect(imageName string, filePath string, created time.Time, pkgs []ftypes.LibraryInfo) (vulns []types.DetectedVulnerability, err error)
}

type Detector struct {
	driverFactory Factory
}

func NewDetector(factory Factory) Detector {
	return Detector{driverFactory: factory}
}

func (d Detector) Detect(_, filePath string, _ time.Time, pkgs []ftypes.LibraryInfo) ([]types.DetectedVulnerability, error) {
	log.Logger.Debugf("Detecting library vulnerabilities, path: %s", filePath)
	driver, err := d.driverFactory.NewDriver(filepath.Base(filePath))
	if err != nil {
		return nil, xerrors.Errorf("failed to new driver: %w", err)
	}

	vulns, err := detect(driver, pkgs)
	if err != nil {
		return nil, xerrors.Errorf("failed to scan %s vulnerabilities: %w", driver.Type(), err)
	}

	return vulns, nil
}

func detect(driver Driver, libs []ftypes.LibraryInfo) ([]types.DetectedVulnerability, error) {
	log.Logger.Infof("Detecting %s vulnerabilities...", driver.Type())
	var vulnerabilities []types.DetectedVulnerability
	for _, lib := range libs {
		v, err := version.NewVersion(lib.Library.Version)
		if err != nil {
			log.Logger.Debugf("invalid version, library: %s, version: %s, error: %s\n",
				lib.Library.Name, lib.Library.Version, err)
			continue
		}

		vulns, err := driver.Detect(lib.Library.Name, v)
		if err != nil {
			return nil, xerrors.Errorf("failed to detect %s vulnerabilities: %w", driver.Type(), err)
		}

		for i := range vulns {
			vulns[i].Layer = lib.Layer
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return vulnerabilities, nil
}
