package utils

import (
	"fmt"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// FormatVersion formats the package version based on epoch, version & release
func FormatVersion(pkg types.Package) string {
	return formatVersion(pkg.Epoch, pkg.Version, pkg.Release)
}

// FormatSrcVersion formats the package version based on source epoch, version & release
func FormatSrcVersion(pkg types.Package) string {
	return formatVersion(pkg.SrcEpoch, pkg.SrcVersion, pkg.SrcRelease)
}

// FormatSrcPackage formats the package name based on source epoch, version & release
func FormatSrcPackage(pkg types.Package) string {
	return formatPackage(pkg.SrcEpoch, pkg.SrcName, pkg.SrcVersion, pkg.SrcRelease)
}

func formatPackage(epoch int, name, version, release string) string {
	n := fmt.Sprintf("%s-%s", name, version)
	if release != "" {
		n = fmt.Sprintf("%s-%s", n, release)
	}
	if epoch != 0 {
		n = fmt.Sprintf("%d:%s", epoch, n)
	}
	return n
}

func formatVersion(epoch int, version, release string) string {
	v := version
	if release != "" {
		v = fmt.Sprintf("%s-%s", v, release)
	}
	if epoch != 0 {
		v = fmt.Sprintf("%d:%s", epoch, v)
	}
	return v
}
