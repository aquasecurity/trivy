package ospkg

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"golang.org/x/xerrors"

	ospkgDetector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Scanner interface {
	Packages(target types.ScanTarget, options types.ScanOptions) types.Result
	Scan(ctx context.Context, target types.ScanTarget, options types.ScanOptions) (types.Result, bool, error)
}

type scanner struct{}

func NewScanner() Scanner {
	return &scanner{}
}

func (s *scanner) Packages(target types.ScanTarget, _ types.ScanOptions) types.Result {
	if len(target.Packages) == 0 || !target.OS.Detected() {
		return types.Result{}
	}

	sort.Sort(target.Packages)
	return types.Result{
		Target:   fmt.Sprintf("%s (%s %s)", target.Name, target.OS.Family, target.OS.Name),
		Class:    types.ClassOSPkg,
		Type:     target.OS.Family,
		Packages: target.Packages,
	}
}

func (s *scanner) Scan(ctx context.Context, target types.ScanTarget, _ types.ScanOptions) (types.Result, bool, error) {
	if !target.OS.Detected() {
		log.Logger.Debug("Detected OS: unknown")
		return types.Result{}, false, nil
	}
	log.Logger.Infof("Detected OS: %s", target.OS.Family)

	if target.OS.Extended {
		// TODO: move the logic to each detector
		target.OS.Name += "-ESM"
	}

	vulns, eosl, err := ospkgDetector.Detect(ctx, "", target.OS.Family, target.OS.Name, target.Repository, time.Time{},
		target.Packages)
	if errors.Is(err, ospkgDetector.ErrUnsupportedOS) {
		return types.Result{}, false, nil
	} else if err != nil {
		return types.Result{}, false, xerrors.Errorf("failed vulnerability detection of OS packages: %w", err)
	}

	artifactDetail := fmt.Sprintf("%s (%s %s)", target.Name, target.OS.Family, target.OS.Name)
	return types.Result{
		Target:          artifactDetail,
		Vulnerabilities: vulns,
		Class:           types.ClassOSPkg,
		Type:            target.OS.Family,
	}, eosl, nil
}
