package sbom

import (
	"io"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type SBOM struct {
	ID           string
	OS           *types.OS
	Packages     []types.PackageInfo
	Applications []types.Application
}

type Unmarshaler interface {
	Unmarshal(io.Reader) (SBOM, error)
}
