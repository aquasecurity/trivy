package branch_protections

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/github"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) []github.BranchProtection {
	return adaptBranchProtections(modules)
}

func adaptBranchProtections(modules terraform.Modules) []github.BranchProtection {
	var branchProtections []github.BranchProtection
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("github_branch_protection") {
			branchProtections = append(branchProtections, adaptBranchProtection(resource))
		}
	}
	return branchProtections
}

func adaptBranchProtection(resource *terraform.Block) github.BranchProtection {

	branchProtection := github.BranchProtection{
		Metadata:             resource.GetMetadata(),
		RequireSignedCommits: resource.GetAttribute("require_signed_commits").AsBoolValueOrDefault(false, resource),
	}

	return branchProtection
}
