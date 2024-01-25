package github

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Repository struct {
	Metadata            defsecTypes.MisconfigMetadata
	Public              defsecTypes.BoolValue
	VulnerabilityAlerts defsecTypes.BoolValue
	Archived            defsecTypes.BoolValue
}

func (r Repository) IsArchived() bool {
	return r.Archived.IsTrue()
}
