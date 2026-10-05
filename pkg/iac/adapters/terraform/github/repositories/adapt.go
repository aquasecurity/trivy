package repositories

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/github"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) []github.Repository {
	return adaptRepositories(modules)
}

func adaptRepositories(modules terraform.Modules) []github.Repository {
	var repositories []github.Repository
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("github_repository") {
			repositories = append(repositories, adaptRepository(modules, resource))
		}
	}
	return repositories
}

func adaptRepository(modules terraform.Modules, resource *terraform.Block) github.Repository {
	repo := github.Repository{
		Metadata:            resource.GetMetadata(),
		Public:              types.Bool(true, resource.GetMetadata()),
		VulnerabilityAlerts: resource.GetAttribute("vulnerability_alerts").AsBoolValueOrDefault(false, resource),
		Archived:            resource.GetAttribute("archived").AsBoolValueOrDefault(false, resource),
	}

	// The standalone github_repository_vulnerability_alerts resource is the recommended
	// approach (vulnerability_alerts on github_repository is deprecated). If present, it takes precedence.
	if blocks := modules.GetReferencingResources(resource, "github_repository_vulnerability_alerts", "repository"); len(blocks) > 0 {
		repo.VulnerabilityAlerts = blocks[0].GetAttribute("enabled").AsBoolValueOrDefault(true, blocks[0])
	}

	privateAttr := resource.GetAttribute("private")
	if privateAttr.IsTrue() {
		repo.Public = types.Bool(false, privateAttr.GetMetadata())
	} else if privateAttr.IsFalse() {
		repo.Public = types.Bool(true, privateAttr.GetMetadata())
	}

	// visibility overrides private
	visibilityAttr := resource.GetAttribute("visibility")
	if visibilityAttr.Equals("private") || visibilityAttr.Equals("internal") {
		repo.Public = types.Bool(false, visibilityAttr.GetMetadata())
	} else if visibilityAttr.Equals("public") {
		repo.Public = types.Bool(true, visibilityAttr.GetMetadata())
	}

	return repo
}
