package parser

import (
	"context"
	"fmt"
	"io"
	"io/fs"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure/arm/parser/armjson"
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

		f, err := p.targetFS.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		deployment, err := p.parseFile(f, path)
		if err != nil {
			return err
		}
		deployments = append(deployments, *deployment)
		return nil
	}); err != nil {
		return nil, err
	}

	return deployments, nil
}

func (p *Parser) parseFile(r io.Reader, filename string) (*azure.Deployment, error) {
	var template Template
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	root := types.NewMetadata(
		types.NewRange(filename, 0, 0, "", p.targetFS),
		"",
	).WithInternal(resolver.NewResolver())

	if err := armjson.Unmarshal(data, &template, &root); err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}
	return p.convertTemplate(template), nil
}

func (p *Parser) convertTemplate(template Template) *azure.Deployment {

	deployment := azure.Deployment{
		Metadata:    template.Metadata,
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
		deployment.Resources = append(deployment.Resources, p.convertResource(resource))
	}

	return &deployment
}

func (p *Parser) convertResource(input Resource) azure.Resource {

	var children []azure.Resource

	for _, child := range input.Resources {
		children = append(children, p.convertResource(child))
	}

	resource := azure.Resource{
		Metadata:   input.Metadata,
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
