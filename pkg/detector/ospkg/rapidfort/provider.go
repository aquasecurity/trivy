package rapidfort

import (
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/driver"
	rfanalyzer "github.com/aquasecurity/trivy/pkg/fanal/analyzer/rapidfort"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// Provider creates a RapidFort driver when the image carries the RapidFort
// curated-image marker. The marker is a fanal CustomResource emitted by the
// rapidfort analyzer (pkg/fanal/analyzer/rapidfort) when it finds the file
// /usr/share/rapidfort/curated.json in the image filesystem.
//
// customResources is the list of CustomResource entries produced by all
// filesystem analyzers during image analysis; each entry's Type field names
// the analyzer that emitted it, so we filter on the RapidFort analyzer's
// type constant to decide whether this is a curated image.
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

// isRapidFortImage returns true when the RapidFort curated-image marker is
// present among the analyzer-emitted CustomResources. Each CustomResource
// has a Type field identifying its producing analyzer; we match on the
// constant rfanalyzer.CustomResourceType (the string "rapidfort-curated"),
// which the rapidfort fanal analyzer sets when it finds the curated.json
// sentinel file in the image.
func isRapidFortImage(customResources []ftypes.CustomResource) bool {
	for _, resource := range customResources {
		if resource.Type == rfanalyzer.CustomResourceType {
			return true
		}
	}
	return false
}
