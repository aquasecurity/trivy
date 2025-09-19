package parser

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure/resolver"
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
	}

	return &deployment
}

func (p *Parser) convertResource(input Resource) azure.Resource {
	var children []azure.Resource

	for _, child := range input.Resources {
		children = append(children, p.convertResource(child))
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


