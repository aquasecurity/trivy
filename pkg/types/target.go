package types

import (
	"github.com/samber/lo"
	"golang.org/x/exp/slices"
)

// VulnType represents vulnerability type
type VulnType = string

// Scanner represents the type of security scanning
type Scanner string

// Scanners is a slice of scanners
type Scanners []Scanner

// Runtime represents a container runtime
type Runtime string

// Runtimes is a slice of runtimes
type Runtimes []Runtime

const (
	// VulnTypeUnknown is a vulnerability type of unknown
	VulnTypeUnknown = VulnType("unknown")

	// VulnTypeOS is a vulnerability type of OS packages
	VulnTypeOS = VulnType("os")

	// VulnTypeLibrary is a vulnerability type of programming language dependencies
	VulnTypeLibrary = VulnType("library")

	// UnknownScanner is the scanner of unknown
	UnknownScanner = Scanner("unknown")

	// NoneScanner is the scanner of none
	NoneScanner = Scanner("none")

	// VulnerabilityScanner is the scanner of vulnerabilities
	VulnerabilityScanner = Scanner("vuln")

	// MisconfigScanner is the scanner of misconfigurations
	MisconfigScanner = Scanner("config")

	// SecretScanner is the scanner of secrets
	SecretScanner = Scanner("secret")

	// RBACScanner is the scanner of rbac assessment
	RBACScanner = Scanner("rbac")

	// LicenseScanner is the scanner of licenses
	LicenseScanner = Scanner("license")

	// DockerRuntime is the docker runtime
	DockerRuntime Runtime = "docker"

	// ContainerdRuntime is the containerd runtime
	ContainerdRuntime Runtime = "containerd"

	// PodmanRuntime is the podman runtime
	PodmanRuntime Runtime = "podman"

	// RemoteRuntime represents a remote scan
	RemoteRuntime Runtime = "remote"
)

var (
	VulnTypes = []string{
		VulnTypeOS,
		VulnTypeLibrary,
	}

	AllScanners = Scanners{
		VulnerabilityScanner,
		MisconfigScanner,
		RBACScanner,
		SecretScanner,
		LicenseScanner,
		NoneScanner,
	}

	// AllImageConfigScanners has a list of available scanners on container image config.
	// The container image in container registries consists of manifest, config and layers.
	// Trivy is also able to detect security issues on the image config.
	AllImageConfigScanners = Scanners{
		MisconfigScanner,
		SecretScanner,
		NoneScanner,
	}

	AllRuntimes = Runtimes{
		DockerRuntime,
		ContainerdRuntime,
		PodmanRuntime,
		RemoteRuntime,
	}
)

func (scanners Scanners) Enabled(s Scanner) bool {
	return slices.Contains(scanners, s)
}

// AnyEnabled returns true if any of the passed scanners is included.
func (scanners Scanners) AnyEnabled(ss ...Scanner) bool {
	for _, s := range ss {
		if scanners.Enabled(s) {
			return true
		}
	}
	return false
}

func (scanners Scanners) StringSlice() []string {
	return lo.Map(scanners, func(s Scanner, _ int) string {
		return string(s)
	})
}

func (runtimes Runtimes) StringSlice() []string {
	return lo.Map(runtimes, func(r Runtime, _ int) string {
		return string(r)
	})
}
