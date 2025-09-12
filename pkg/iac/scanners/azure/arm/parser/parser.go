package parser

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure/resolver"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

type Parser struct {
	targetFS fs.FS
	logger   *log.Logger
}

func New(targetFS fs.FS) *Parser {
	return &Parser{
		targetFS: targetFS,
		logger:   log.WithPrefix("arm parser"),
	}
}

func (p *Parser) ParseFS(ctx context.Context, dir string) ([]azure.Deployment, error) {

	var deployments []azure.Deployment

	if err := fs.WalkDir(p.targetFS, dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if entry.IsDir() {
			return nil
		}

		deployment, err := p.parseFile(path)
		if err != nil {
			p.logger.Error("Failed to parse file", log.FilePath(path), log.Err(err))
			return nil
		}

		deployments = append(deployments, *deployment)
		return nil
	}); err != nil {
		return nil, err
	}

	return deployments, nil
}

func (p *Parser) parseFile(path string) (*azure.Deployment, error) {
	template, err := ParseTemplate(p.targetFS, path)
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}
	return p.convertTemplate(template), nil
}

func (p *Parser) convertTemplate(template *Template) *azure.Deployment {

	deployment := azure.Deployment{
		Metadata:    lo.FromPtr(template.Metadata),
		TargetScope: azure.ScopeResourceGroup, // TODO: override from --resource-group?
		Parameters:  nil,
		Variables:   nil,
		Resources:   nil,
		Outputs:     nil,
	}

	if r, ok := template.Metadata.Internal().(resolver.Resolver); ok {
		r.SetDeployment(&deployment)
	}

	// TODO: the references passed here should probably not be the name - maybe params.NAME.DefaultValue?
	for name, param := range template.Parameters {
		deployment.Parameters = append(deployment.Parameters, azure.Parameter{
			Variable: azure.Variable{
				Name:  name,
				Value: param.DefaultValue,
			},
			Default:    param.DefaultValue,
			Decorators: nil,
		})
	}

	for name, variable := range template.Variables {
		deployment.Variables = append(deployment.Variables, azure.Variable{
			Name:  name,
			Value: variable,
		})
	}

	for name, output := range template.Outputs {
		deployment.Outputs = append(deployment.Outputs, azure.Output{
			Name:  name,
			Value: output,
		})
	}

	for _, resource := range template.Resources {
		convertedResource := p.convertResource(resource)
		deployment.Resources = append(deployment.Resources, convertedResource)
		
		// If this is a Microsoft.Resources/deployments resource, also add its nested resources to the main deployment
		if convertedResource.Type.AsString() == "Microsoft.Resources/deployments" {
			nestedResources := p.extractNestedTemplateResources(Resource{
				Metadata: &convertedResource.Metadata,
				innerResource: innerResource{
					APIVersion: convertedResource.APIVersion,
					Type:       convertedResource.Type,
					Kind:       convertedResource.Kind,
					Name:       convertedResource.Name,
					Location:   convertedResource.Location,
					Properties: convertedResource.Properties,
					Resources:  []Resource{},
				},
			})
			// Add nested resources directly to the main deployment
			deployment.Resources = append(deployment.Resources, nestedResources...)
		}
	}

	return &deployment
}

func (p *Parser) convertResource(input Resource) azure.Resource {

	var children []azure.Resource

	for _, child := range input.Resources {
		children = append(children, p.convertResource(child))
	}

	// Handle nested templates in Microsoft.Resources/deployments (Bicep modules)
	if input.Type.AsString() == "Microsoft.Resources/deployments" {
		nestedResources := p.extractNestedTemplateResources(input)
		children = append(children, nestedResources...)
	}

	resource := azure.Resource{
		Metadata:   lo.FromPtr(input.Metadata),
		APIVersion: input.APIVersion,
		Type:       input.Type,
		Kind:       input.Kind,
		Name:       input.Name,
		Location:   input.Location,
		Properties: input.Properties,
		Resources:  children,
	}

	return resource
}

func (p *Parser) extractNestedTemplateResources(input Resource) []azure.Resource {
	var nestedResources []azure.Resource

	// Extract the nested template from properties.template
	if input.Properties.Raw() == nil {
		return nestedResources
	}

	properties, ok := input.Properties.Raw().(map[string]any)
	if !ok {
		return nestedResources
	}

	template, ok := properties["template"]
	if !ok {
		return nestedResources
	}

	templateMap, ok := template.(map[string]any)
	if !ok {
		return nestedResources
	}

	// Extract resources from the nested template
	resources, ok := templateMap["resources"]
	if !ok {
		return nestedResources
	}

	resourcesArray, ok := resources.([]any)
	if !ok {
		// Handle dictionary resources (Bicep modules)
		if resourcesMap, ok := resources.(map[string]any); ok {
			for name, resourceData := range resourcesMap {
				if resourceMap, ok := resourceData.(map[string]any); ok {
					resource := convertMapToResource(resourceMap, 0)
					// Set the name from the dictionary key if not already set
					if resource.Name.Raw() == nil {
						resource.Name = azure.NewValue(name, types.NewMetadata(
							types.NewRange("", 0, 0, "", nil),
							"",
						))
					}
					nestedResources = append(nestedResources, p.convertResource(resource))
				}
			}
		}
		return nestedResources
	}

	// Handle array resources (standard ARM templates)
	for i, resourceData := range resourcesArray {
		if resourceMap, ok := resourceData.(map[string]any); ok {
			resource := convertMapToResource(resourceMap, i)
			nestedResources = append(nestedResources, p.convertResource(resource))
		}
	}

	return nestedResources
}
