// Package all registers all built-in library vulnerability vendors.
// Import it for side effects to enable vendor-specific advisory detection
// (e.g., Seal Security):
//
//	import _ "github.com/aquasecurity/trivy/pkg/detector/library/all"
package all

import (
	_ "github.com/aquasecurity/trivy/pkg/detector/library/seal"
)
