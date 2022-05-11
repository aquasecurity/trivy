package github

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type Repository struct {
	types.Metadata
	Public              types.BoolValue
	VulnerabilityAlerts types.BoolValue
	Archived            types.BoolValue
}

func (r Repository) IsArchived() bool {
	return r.Archived.IsTrue()
}
