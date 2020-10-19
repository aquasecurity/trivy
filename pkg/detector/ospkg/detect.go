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

// nolint: gocyclo
// TODO: fix cyclometic complexity by removing default
func newDriver(osFamily, osName string) Driver {
	// TODO: use DI and change struct names
	switch osFamily {
	case fos.Alpine:
		return alpine.NewScanner()
	case fos.Debian:
		return debian.NewScanner()
	case fos.Ubuntu:
		return ubuntu.NewScanner()
	case fos.RedHat, fos.CentOS:
		return redhat.NewScanner()
	case fos.Amazon:
		return amazon.NewScanner()
	case fos.Oracle:
		return oracle.NewScanner()
	case fos.OpenSUSELeap:
		return suse.NewScanner(suse.OpenSUSE)
	case fos.SLES:
		return suse.NewScanner(suse.SUSEEnterpriseLinux)
	case fos.Photon:
		return photon.NewScanner()
	default:
		log.Logger.Warnf("unsupported os : %s", osFamily)
		return nil
	}
}
