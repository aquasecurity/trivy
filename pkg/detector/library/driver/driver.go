package driver

import (
	"context"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Driver defines operations for language-specific package scan
type Driver interface {
	Detect(context.Context, ftypes.Package) ([]types.DetectedVulnerability, error)
	Type() string
}

// Provider creates a specialized driver based on the environment
type Provider func(libType ftypes.LangType, pkgs []ftypes.Package) Driver
