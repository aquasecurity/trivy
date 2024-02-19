package datafactory

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type DataFactory struct {
	DataFactories []Factory
}

type Factory struct {
	Metadata            iacTypes.Metadata
	EnablePublicNetwork iacTypes.BoolValue
}
