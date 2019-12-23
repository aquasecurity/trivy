package ospkg

import (
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	_ "github.com/aquasecurity/fanal/analyzer/command/apk"
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/os/amazonlinux"
	_ "github.com/aquasecurity/fanal/analyzer/os/debianbase"
	_ "github.com/aquasecurity/fanal/analyzer/os/redhatbase"
	_ "github.com/aquasecurity/fanal/analyzer/os/suse"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/dpkg"
	"github.com/aquasecurity/fanal/extractor"
	ftypes "github.com/aquasecurity/fanal/types"
	detector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Scanner struct {
	detector detector.Operation
}

func NewScanner(detector detector.Operation) Scanner {
	return Scanner{detector: detector}
}

func (s Scanner) Scan(files extractor.FileMap) (string, string, []types.DetectedVulnerability, error) {
	os, err := analyzer.GetOS(files)
	if err != nil {
		return "", "", nil, xerrors.Errorf("failed to analyze OS: %w", err)
	}
	log.Logger.Debugf("OS family: %s, OS version: %s", os.Family, os.Name)

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

	vulns, eosl, err := s.detector.Detect(os.Family, os.Name, pkgs)
	if err != nil {
		return "", "", nil, xerrors.Errorf("failed to detect vulnerabilities: %w", err)
	}
	if eosl {
		log.Logger.Warnf("This OS version is no longer supported by the distribution: %s %s", os.Family, os.Name)
		log.Logger.Warnf("The vulnerability detection may be insufficient because security updates are not provided")
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
