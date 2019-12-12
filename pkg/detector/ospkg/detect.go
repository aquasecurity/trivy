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
	Detect(string, string, []analyzer.Package) ([]types.DetectedVulnerability, bool, error)
}

type Driver interface {
	Detect(string, []analyzer.Package) ([]types.DetectedVulnerability, error)
	IsSupportedVersion(string, string) bool
}

type Detector struct{}

func (d Detector) Detect(osFamily, osName string, pkgs []analyzer.Package) ([]types.DetectedVulnerability, bool, error) {
	driver := newDriver(osFamily, osName)
	if driver == nil {
		return nil, false, ErrUnsupportedOS
	}

	eosl := !driver.IsSupportedVersion(osFamily, osName)

	vulns, err := driver.Detect(osName, pkgs)
	if err != nil {
		return nil, false, xerrors.Errorf("failed detection: %w", err)
	}

	return vulns, eosl, nil
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
