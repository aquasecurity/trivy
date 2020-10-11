package ospkg

import (
	"time"

	"github.com/google/wire"
	"golang.org/x/xerrors"

	fos "github.com/aquasecurity/fanal/analyzer/os"
	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/alpine"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/amazon"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/debian"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/oracle"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/photon"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/redhat"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/suse"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/ubuntu"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	// ErrUnsupportedOS defines error for unsupported OS
	ErrUnsupportedOS = xerrors.New("unsupported os")

	// SuperSet binds dependencies for OS scan
	SuperSet = wire.NewSet(
		wire.Struct(new(Detector)),
		wire.Bind(new(Operation), new(Detector)),
	)
)

// Operation defines operation of OSpkg scan
type Operation interface {
	Detect(string, string, string, time.Time, []ftypes.Package) ([]types.DetectedVulnerability, bool, error)
}

// Driver defines operations for OS package scan
type Driver interface {
	Detect(string, []ftypes.Package) ([]types.DetectedVulnerability, error)
	IsSupportedVersion(string, string) bool
}

// Detector implements Operation
type Detector struct{}

// Detect detects the vulnerabilities
func (d Detector) Detect(_, osFamily, osName string, _ time.Time, pkgs []ftypes.Package) ([]types.DetectedVulnerability, bool, error) {
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
		return d
	case fos.Debian:
		d = debian.NewScanner()
		return d
	case fos.Ubuntu:
		d = ubuntu.NewScanner()
		return d
	case fos.RedHat, fos.CentOS:
		d = redhat.NewScanner()
		return d
	case fos.Amazon:
		d = amazon.NewScanner()
		return d
	case fos.Oracle:
		d = oracle.NewScanner()
		return d
	case fos.OpenSUSELeap:
		d = suse.NewScanner(suse.OpenSUSE)
		return d
	case fos.SLES:
		d = suse.NewScanner(suse.SUSEEnterpriseLinux)
		return d
	case fos.Photon:
		d = photon.NewScanner()
		return d
	}
	log.Logger.Warnf("unsupported os : %s", osFamily)
	return nil
}
