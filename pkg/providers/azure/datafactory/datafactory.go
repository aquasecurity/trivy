package datafactory

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type DataFactory struct {
	DataFactories []Factory
}

type Factory struct {
	Metadata            defsecTypes.MisconfigMetadata
	EnablePublicNetwork defsecTypes.BoolValue
}
