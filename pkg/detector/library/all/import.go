// Package all registers all built-in library vulnerability vendors.
// Import it for side effects to enable vendor-specific advisory detection
// (e.g., Seal Security):
//
//	import _ "github.com/aquasecurity/trivy/pkg/detector/library/all"
//
// Downstream builds that embed Trivy as a library can opt out of the
// built-in vendor set by importing individual vendor packages instead.
package all

import (
	_ "github.com/aquasecurity/trivy/pkg/detector/library/seal"
)
