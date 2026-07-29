// Package chainguard detects vulnerabilities in the APK packages of a
// Chainguard image. The detection itself is shared with Wolfi in the
// chainguardosv package, because both distros are covered by the same feed.
package chainguard

import (
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/chainguard"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/chainguardosv"
)

// Scanner implements the Chainguard scanner. It is a distinct type from the Wolfi
// scanner it shares an implementation with, so that callers can still tell the
// two apart.
type Scanner struct {
	*chainguardosv.Scanner
}

// NewScanner is the factory method for Scanner.
func NewScanner() *Scanner {
	return &Scanner{chainguardosv.NewScanner(chainguard.NewVulnSrc(), "Chainguard")}
}
