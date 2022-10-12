package types

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	stypes "github.com/spdx/tools-golang/spdx"
)

type SBOM struct {
	OS           *types.OS
	Packages     []types.PackageInfo
	Applications []types.Application

	CycloneDX *types.CycloneDX
	SPDX      *stypes.Document2_2
}

type SBOMSource = string

const (
	SBOMSourceRekor = SBOMSource("rekor")
)

var (
	SBOMSources = []string{
		SBOMSourceRekor,
	}
)
