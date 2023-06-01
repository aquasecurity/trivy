package ospkg

import (
	"fmt"
	"sort"
	"time"

	"golang.org/x/xerrors"

	ospkgDetector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Scanner interface {
	Packages(target string, detail ftypes.ArtifactDetail, options types.ScanOptions) types.Result
	Scan(target string, detail ftypes.ArtifactDetail, options types.ScanOptions) (types.Result, bool, error)
}

type scanner struct{}

func NewScanner() Scanner {
	return &scanner{}
}

func (s *scanner) Packages(target string, detail ftypes.ArtifactDetail, options types.ScanOptions) types.Result {
	if len(detail.Packages) == 0 || !detail.OS.Detected() {
		return types.Result{}
	}

	pkgs := detail.Packages
	if options.ScanRemovedPackages {
		pkgs = mergePkgs(pkgs, detail.ImageConfig.Packages)
	}
	sort.Sort(pkgs)
	return types.Result{
		Target:   fmt.Sprintf("%s (%s %s)", target, detail.OS.Family, detail.OS.Name),
		Class:    types.ClassOSPkg,
		Type:     detail.OS.Family,
		Packages: pkgs,
	}
}

func (s *scanner) Scan(target string, detail ftypes.ArtifactDetail, options types.ScanOptions) (types.Result, bool, error) {
	if !detail.OS.Detected() {
		log.Logger.Debug("Detected OS: unknown")
		return types.Result{}, false, nil
	}
	log.Logger.Infof("Detected OS: %s", detail.OS.Family)

	pkgs := detail.Packages
	if options.ScanRemovedPackages {
		pkgs = mergePkgs(pkgs, detail.ImageConfig.Packages)
	}

	if detail.OS.Extended {
		// TODO: move the logic to each detector
		detail.OS.Name += "-ESM"
	}

	vulns, eosl, err := ospkgDetector.Detect("", detail.OS.Family, detail.OS.Name, detail.Repository, time.Time{}, pkgs)
	if err == ospkgDetector.ErrUnsupportedOS {
		return types.Result{}, false, nil
	} else if err != nil {
		return types.Result{}, false, xerrors.Errorf("failed vulnerability detection of OS packages: %w", err)
	}

	artifactDetail := fmt.Sprintf("%s (%s %s)", target, detail.OS.Family, detail.OS.Name)
	return types.Result{
		Target:          artifactDetail,
		Vulnerabilities: vulns,
		Class:           types.ClassOSPkg,
		Type:            detail.OS.Family,
	}, eosl, nil
}

func mergePkgs(pkgs, pkgsFromCommands []ftypes.Package) []ftypes.Package {
	// pkg has priority over pkgsFromCommands
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
