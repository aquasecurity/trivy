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