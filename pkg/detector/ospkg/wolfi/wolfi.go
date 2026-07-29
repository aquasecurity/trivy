// Package wolfi detects vulnerabilities in the APK packages of a Wolfi image.
// The detection itself is shared with Chainguard in the chainguardosv package,
// because both distros are covered by the same feed.
package wolfi

import (
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/wolfi"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/chainguardosv"
)

// Scanner implements the Wolfi scanner. It is a distinct type from the Chainguard
// scanner it shares an implementation with, so that callers can still tell the
// two apart.
type Scanner struct {
	*chainguardosv.Scanner
}

// NewScanner is the factory method for Scanner.
func NewScanner() *Scanner {
	return &Scanner{chainguardosv.NewScanner(wolfi.NewVulnSrc(), "Wolfi")}
}
