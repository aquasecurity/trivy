package ospkg

import (
	"errors"

	"github.com/aquasecurity/fanal/analyzer"
	_ "github.com/aquasecurity/fanal/analyzer/command/apk"
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
	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/xerrors"
)

var (
	ErrUnsupportedOS = errors.New("unsupported os")
)

type Scanner struct {
	os       analyzer.OS
	files    extractor.FileMap
	detector DetectorOperation
}

func NewScanner(remoteURL, token string, files extractor.FileMap) (Scanner, error) {
	os, err := analyzer.GetOS(files)
	if err != nil {
		return Scanner{}, xerrors.Errorf("failed to analyze OS: %w", err)
	}
	log.Logger.Debugf("OS family: %s, OS version: %s", os.Family, os.Name)

	detector := NewDetector(os.Family, os.Name, remoteURL, token)
	if detector == nil {
		return Scanner{}, ErrUnsupportedOS
	}

	return Scanner{
		os:       os,
		files:    files,
		detector: detector,
	}, nil
}

func (s Scanner) Scan() (string, string, []types.DetectedVulnerability, error) {
	pkgs, err := analyzer.GetPackages(s.files)
	if err != nil {
		if xerrors.Is(err, ftypes.ErrNoRpmCmd) {
			log.Logger.Error("'rpm' command is not installed")
		}
		return "", "", nil, xerrors.Errorf("failed to analyze OS packages: %w", err)
	}
	log.Logger.Debugf("the number of packages: %d", len(pkgs))

	pkgsFromCommands, err := analyzer.GetPackagesFromCommands(s.os, s.files)
	if err != nil {
		return "", "", nil, xerrors.Errorf("failed to analyze OS packages: %w", err)
	}
	log.Logger.Debugf("the number of packages from commands: %d", len(pkgsFromCommands))

	pkgs = mergePkgs(pkgs, pkgsFromCommands)
	log.Logger.Debugf("the number of packages: %d", len(pkgs))

	vulns, err := s.detector.Detect(s.os.Family, s.os.Name, pkgs)
	if err != nil {
		return "", "", nil, xerrors.Errorf("failed to detect vulnerabilities: %w", err)
	}

	return s.os.Family, s.os.Name, vulns, nil
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
