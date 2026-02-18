package ospkg

import (
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/driver"
	"github.com/aquasecurity/trivy/pkg/types"
)

// NewTestDetector creates a Detector with custom target and driver for testing.
func NewTestDetector(target types.ScanTarget, drv driver.Driver) *Detector {
	return &Detector{
		target: target,
		driver: drv,
	}
}
