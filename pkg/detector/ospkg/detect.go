package ospkg

import (
	"github.com/aquasecurity/trivy/internal/rpc/client/ospkg"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg/alpine"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg/amazon"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg/debian"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg/oracle"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg/redhat"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg/ubuntu"

	"github.com/aquasecurity/fanal/analyzer"
	fos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/types"
)

type DetectorOperation interface {
	Detect(string, string, []analyzer.Package) ([]types.DetectedVulnerability, error)
}

type ScannerOperation interface {
	Detect(string, []analyzer.Package) ([]types.DetectedVulnerability, error)
	IsSupportedVersion(string, string) bool
}

func NewDetector(osFamily, osName, remoteURL, token string) DetectorOperation {
	var s ScannerOperation
	switch osFamily {
	case fos.Alpine:
		s = alpine.NewScanner()
	case fos.Debian:
		s = debian.NewScanner()
	case fos.Ubuntu:
		s = ubuntu.NewScanner()
	case fos.RedHat, fos.CentOS:
		s = redhat.NewScanner()
	case fos.Amazon:
		s = amazon.NewScanner()
	case fos.Oracle:
		s = oracle.NewScanner()
	default:
		log.Logger.Warnf("unsupported os : %s", osFamily)
		return nil
	}

	if !s.IsSupportedVersion(osFamily, osName) {
		log.Logger.Warnf("This OS version is no longer supported by the distribution: %s %s", osFamily, osName)
		log.Logger.Warnf("The vulnerability detection may be insufficient because security updates are not provided")
	}

	if remoteURL != "" {
		return ospkg.NewDetectClient(remoteURL, token)
	}
	return Detector{scanner: s}
}

type Detector struct {
	scanner ScannerOperation
}

func (d Detector) Detect(osFamily, osName string, pkgs []analyzer.Package) ([]types.DetectedVulnerability, error) {
	vulns, err := d.scanner.Detect(osName, pkgs)
	if err != nil {
		return nil, err
	}

	return vulns, nil
}
