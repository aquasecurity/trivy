package github

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type BranchProtection struct {
	Metadata             iacTypes.Metadata
	RequireSignedCommits iacTypes.BoolValue
}
