// Package all registers all built-in library vulnerability suppliers.
// Import it for side effects to enable supplier-specific advisory detection
// (e.g., Seal Security):
//
//	import _ "github.com/aquasecurity/trivy/pkg/detector/library/all"
package all

import (
	_ "github.com/aquasecurity/trivy/pkg/detector/library/seal"
)
