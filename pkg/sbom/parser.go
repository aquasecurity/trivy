package sbom

import (
	"io"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type SBOMFormat string

type Parser interface {
	Parse(io.Reader) (string, *types.OS, []types.PackageInfo, []types.Application, error)
	Type() SBOMFormat
}
