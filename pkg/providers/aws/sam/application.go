package sam

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Application struct {
	Metadata     defsecTypes.MisconfigMetadata
	LocationPath defsecTypes.StringValue
	Location     Location
}

type Location struct {
	Metadata        defsecTypes.MisconfigMetadata
	ApplicationID   defsecTypes.StringValue
	SemanticVersion defsecTypes.StringValue
}
