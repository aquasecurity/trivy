package ospkg

import (
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/alpine"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/amazon"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/debian"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/oracle"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/redhat"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/ubuntu"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/google/wire"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	fos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	ErrUnsupportedOS = xerrors.New("unsupported os")

	SuperSet = wire.NewSet(
		wire.Struct(new(Detector)),
		wire.Bind(new(Operation), new(Detector)),
	)
)

type Operation interface {
	Detect(string, string, []analyzer.Package) ([]types.DetectedVulnerability, error)
}

type Driver interface {
	Detect(string, []analyzer.Package) ([]types.DetectedVulnerability, error)
	IsSupportedVersion(string, string) bool
}

type Detector struct{}

func (d Detector) Detect(osFamily, osName string, pkgs []analyzer.Package) ([]types.DetectedVulnerability, error) {
	driver := newDriver(osFamily, osName)
	if driver == nil {
		return nil, ErrUnsupportedOS
	}

	if !driver.IsSupportedVersion(osFamily, osName) {
		log.Logger.Warnf("This OS version is no longer supported by the distribution: %s %s", osFamily, osName)
		log.Logger.Warnf("The vulnerability detection may be insufficient because security updates are not provided")
	}

	vulns, err := driver.Detect(osName, pkgs)
	if err != nil {
		return nil, xerrors.Errorf("failed detection: %w", err)
	}

	return vulns, nil
}

func newDriver(osFamily, osName string) Driver {
	// TODO: use DI and change struct names
	var d Driver
	switch osFamily {
	case fos.Alpine:
		d = alpine.NewScanner()
	case fos.Debian:
		d = debian.NewScanner()
	case fos.Ubuntu:
		d = ubuntu.NewScanner()
	case fos.RedHat, fos.CentOS:
		d = redhat.NewScanner()
	case fos.Amazon:
		d = amazon.NewScanner()
	case fos.Oracle:
		d = oracle.NewScanner()
	default:
		log.Logger.Warnf("unsupported os : %s", osFamily)
		return nil
	}
	return d
}
