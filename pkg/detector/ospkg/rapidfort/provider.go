package rapidfort

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/detector/ospkg/driver"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

const (
	// maintainerLabel is the Docker image config label used by RapidFort curated images.
	maintainerLabel = "maintainer"

	// rapidfortIdentifier is the string that must appear in the maintainer label value.
	rapidfortIdentifier = "rapidfort"
)

// Provider creates a RapidFort driver if the image has a RapidFort maintainer label.
func Provider(osFamily ftypes.OSType, _ []ftypes.Package, labels map[string]string) driver.Driver {
	if !isRapidFortImage(labels) {
		return nil
	}
	switch osFamily {
	case ftypes.Ubuntu, ftypes.Alpine, ftypes.RedHat:
		return NewScanner(osFamily)
	}
	return nil
}

// isRapidFortImage returns true when the image config labels identify this as a
// RapidFort curated image (maintainer label contains "rapidfort", case-insensitive).
func isRapidFortImage(labels map[string]string) bool {
	val, ok := labels[maintainerLabel]
	if !ok {
		return false
	}
	return strings.Contains(strings.ToLower(val), rapidfortIdentifier)
}
