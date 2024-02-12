package github

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type BranchProtection struct {
	Metadata             defsecTypes.Metadata
	RequireSignedCommits defsecTypes.BoolValue
}

func (b BranchProtection) RequiresSignedCommits() bool {
	return b.RequireSignedCommits.IsTrue()
}
