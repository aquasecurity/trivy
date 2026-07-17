package rapidfort

import (
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/driver"
	rfanalyzer "github.com/aquasecurity/trivy/pkg/fanal/analyzer/rapidfort"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// Provider creates a RapidFort driver when the image carries the RapidFort
// curated-image marker emitted by the rapidfort filesystem analyzer.
func Provider(osFamily ftypes.OSType, _ []ftypes.Package, customResources []ftypes.CustomResource) driver.Driver {
	if !isRapidFortImage(customResources) {
		return nil
	}
	switch osFamily {
	case ftypes.Ubuntu, ftypes.Alpine, ftypes.RedHat:
		return NewScanner(osFamily)
	}
	return nil
}

// isRapidFortImage returns true when a RapidFort curated-image marker is
// present in the analyzer output. The marker is produced by the fanal
// analyzer for /usr/share/rapidfort/curated.json.
func isRapidFortImage(customResources []ftypes.CustomResource) bool {
	for _, r := range customResources {
		if r.Type == rfanalyzer.CustomResourceType {
			return true
		}
	}
	return false
}
