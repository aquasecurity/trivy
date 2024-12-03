package ospkg

import (
	"context"
	"fmt"
	"sort"
	"time"

	"golang.org/x/xerrors"

	ospkgDetector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Scanner interface {
	Scan(ctx context.Context, target types.ScanTarget, options types.ScanOptions) (types.Result, bool, error)
}

type scanner struct{}

func NewScanner() Scanner {
	return &scanner{}
}

func (s *scanner) Scan(ctx context.Context, target types.ScanTarget, opts types.ScanOptions) (types.Result, bool, error) {
	if !target.OS.Detected() {
		log.Debug("Detected OS: unknown")
		return types.Result{}, false, nil
	}
	log.Info("Detected OS", log.String("family",
		string(target.OS.Family)), log.String("version", target.OS.Name))

	if target.OS.Extended {
		// TODO: move the logic to each detector
		target.OS.Name += "-ESM"
	}

	result := types.Result{
		Target: fmt.Sprintf("%s (%s %s)", target.Name, target.OS.Family, target.OS.Name),
		Class:  types.ClassOSPkg,
		Type:   target.OS.Family,
	}

	sort.Sort(target.Packages)
	result.Packages = target.Packages

	if !opts.Scanners.Enabled(types.VulnerabilityScanner) {
		// Return packages only
		return result, false, nil
	}

	vulns, eosl, err := ospkgDetector.Detect(ctx, "", target.OS.Family, target.OS.Name, target.Repository, time.Time{},
		target.Packages)
	if err != nil {
		// Return a result for those who want to override the error handling.
		return result, false, xerrors.Errorf("failed vulnerability detection of OS packages: %w", err)
	}
	result.Vulnerabilities = vulns

	return result, eosl, nil
}
