package ospkg

import (
	"github.com/aquasecurity/fanal/analyzer"
	_ "github.com/aquasecurity/fanal/analyzer/command/apk"
	fos "github.com/aquasecurity/fanal/analyzer/os"
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/os/amazonlinux"
	_ "github.com/aquasecurity/fanal/analyzer/os/debianbase"
	_ "github.com/aquasecurity/fanal/analyzer/os/opensuse"
	_ "github.com/aquasecurity/fanal/analyzer/os/redhatbase"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/dpkg"
	"github.com/aquasecurity/fanal/extractor"
	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg/alpine"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg/amazon"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg/debian"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg/redhat"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg/ubuntu"
	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/xerrors"
)

type Scanner interface {
	Detect(string, []analyzer.Package) ([]types.DetectedVulnerability, error)
	IsSupportedVersion(string, string) bool
}

func Scan(files extractor.FileMap) (string, string, []types.DetectedVulnerability, error) {
	os, err := analyzer.GetOS(files)
	if err != nil {
		return "", "", nil, xerrors.Errorf("failed to analyze OS: %w", err)
	}
	log.Logger.Debugf("OS family: %s, OS version: %s", os.Family, os.Name)

	var s Scanner
	switch os.Family {
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
	default:
		log.Logger.Warnf("unsupported os : %s", os.Family)
		return "", "", nil, nil
	}
	pkgs, err := analyzer.GetPackages(files)
	if err != nil {
		if xerrors.Is(err, ftypes.ErrNoRpmCmd) {
			log.Logger.Error("'rpm' command is not installed")
		}
		return "", "", nil, xerrors.Errorf("failed to analyze OS packages: %w", err)
	}
	log.Logger.Debugf("the number of packages: %d", len(pkgs))

	pkgsFromCommands, err := analyzer.GetPackagesFromCommands(os, files)
	if err != nil {
		return "", "", nil, xerrors.Errorf("failed to analyze OS packages: %w", err)
	}
	log.Logger.Debugf("the number of packages from commands: %d", len(pkgsFromCommands))

	pkgs = mergePkgs(pkgs, pkgsFromCommands)
	log.Logger.Debugf("the number of packages: %d", len(pkgs))

	if !s.IsSupportedVersion(os.Family, os.Name) {
		log.Logger.Warnf("This OS version is no longer supported by the distribution: %s %s", os.Family, os.Name)
		log.Logger.Warnf("The vulnerability detection may be insufficient because security updates are not provided")
	}

	vulns, err := s.Detect(os.Name, pkgs)
	if err != nil {
		return "", "", nil, xerrors.Errorf("failed to detect vulnerabilities: %w", err)
	}

	return os.Family, os.Name, vulns, nil
}

func mergePkgs(pkgs, pkgsFromCommands []analyzer.Package) []analyzer.Package {
	uniqPkgs := map[string]struct{}{}
	for _, pkg := range pkgs {
		uniqPkgs[pkg.Name] = struct{}{}
	}
	for _, pkg := range pkgsFromCommands {
		if _, ok := uniqPkgs[pkg.Name]; ok {
			continue
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs
}
