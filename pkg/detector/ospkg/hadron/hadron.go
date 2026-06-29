// Package hadron provides an OS package vulnerability driver for Hadron Linux.
//
// Hadron ships pristine upstream package versions and currently has no advisory
// data source in trivy-db. This driver is therefore a no-op: it registers the
// Hadron OS family so that scans complete without an "unsupported os" error and
// reports the installed packages, but it does not match any vulnerabilities.
//
// When a Hadron advisory source becomes available (e.g. a name-keyed secdb-style
// source in trivy-db, as used by Alpine/Wolfi/Chainguard), only Detect needs to
// be updated to query it.
package hadron

import (
	"context"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Scanner implements the OS package driver for Hadron Linux.
type Scanner struct{}

// NewScanner returns a new Hadron scanner.
func NewScanner() *Scanner {
	return &Scanner{}
}

// Detect returns no vulnerabilities. Hadron has no advisory data source yet.
func (s *Scanner) Detect(ctx context.Context, _ string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.InfoContext(ctx, "Hadron has no vulnerability data source; reporting packages only",
		log.Int("pkg_num", len(pkgs)))
	return nil, nil
}

// IsSupportedVersion always returns true. Hadron is a rolling release, so there
// is no end-of-service-life concept.
func (s *Scanner) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	return true
}
