package github

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type BranchProtection struct {
	Metadata             defsecTypes.MisconfigMetadata
	RequireSignedCommits defsecTypes.BoolValue
}

func (b BranchProtection) RequiresSignedCommits() bool {
	return b.RequireSignedCommits.IsTrue()
}
