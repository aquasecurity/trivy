package driver

import (
	"context"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Driver defines operations for OS package scan
type Driver interface {
	Detect(context.Context, string, *ftypes.Repository, []ftypes.Package) ([]types.DetectedVulnerability, error)
	IsSupportedVersion(context.Context, ftypes.OSType, string) bool
}

// Provider creates a specialized driver based on the environment
type Provider func(osFamily ftypes.OSType, pkgs []ftypes.Package) Driver

// LabelProvider creates a specialized driver based on the environment and image labels.
// Use this when detection requires access to container image config labels.
type LabelProvider func(osFamily ftypes.OSType, pkgs []ftypes.Package, labels map[string]string) Driver

// ThirdPartyAware is an optional interface a Driver can implement to indicate
// it handles third-party packages itself and should receive them unfiltered.
// Drivers that do NOT implement this interface have third-party packages stripped
// before Detect is called (the default behavior).
type ThirdPartyAware interface {
	IncludesThirdParty() bool
}
