package parser

import (
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
)

// extractNestedTemplateResources extracts resources from nested templates in Microsoft.Resources/deployments resources.
// This functionality is currently not enabled and will be implemented in a separate PR.
func (p *Parser) extractNestedTemplateResources(input Resource) []azure.Resource {
	// Implementation will be added in a separate PR
	return nil
}
