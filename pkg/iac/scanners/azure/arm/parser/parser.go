package parser

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"strconv"
	"strings"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure/resolver"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
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
			println(err.Error())
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

func (p *Parser) parseFile(r io.Reader, filename string) (*azure.Deployment, error) {

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	data = xjson.ToRFC8259(data)

	lr := xjson.NewLineReader(bytes.NewReader(data))

	var template Template

	rootMetadata := types.NewMetadata(
		types.NewRange(filename, 0, 0, "", p.targetFS),
		"",
	).WithInternal(resolver.NewResolver())

	if err := json.UnmarshalRead(lr, &template, json.WithUnmarshalers(
		json.JoinUnmarshalers(
			xjson.UnmarshalerWithObjectLocation(lr, func() xjson.DecodeHook {
				stack := map[jsontext.Pointer]*types.Metadata{
					"": {},
				}
				return xjson.DecodeHook{
					Before: func(dec *jsontext.Decoder, obj any) {
						pointer := dec.StackPointer()
						if pointer != "" {
							// Do not overwrite metadata if we have already set it below
							if _, exists := stack[pointer]; !exists {
								if _, ok := obj.(MetadataReceiver); ok {
									stack[pointer] = &types.Metadata{}
								}

							}
						}

						// The array node is visited after all its elements,
						// so the parent metadata must already be created.
						// parent := pointer.Parent()
						// if _, err := strconv.Atoi(pointer.Parent().LastToken()); err == nil {
						// 	stack[parent] = &types.Metadata{}
						// }
					},
					After: func(dec *jsontext.Decoder, obj any, loc ftypes.Location) {
						pointer := dec.StackPointer()
						ref := buildNodeRef(pointer.Tokens())
						rng := types.NewRange(filename, loc.StartLine, loc.EndLine, "", p.targetFS)
						metadata := types.NewMetadata(rng, ref)

						if pointer == "" {
							metadata.SetParentPtr(&rootMetadata)
						} else {
							parentPtr := pointer.Parent()
							for parentPtr != "" {
								if parent, ok := stack[parentPtr]; ok {
									metadata.SetParentPtr(parent)
									break
								}
								parentPtr = parentPtr.Parent()
							}

							if parentPtr == "" {
								metadata.SetParentPtr(&template.Metadata)
							}
						}

						existingMeta, ok := stack[pointer]
						if ok {
							*existingMeta = metadata
						} else {
							stack[pointer.Parent()] = &metadata
							existingMeta = &metadata
						}

						if mr, ok := obj.(MetadataReceiver); ok {
							mr.SetMetadata(*existingMeta)
						}
					},
				}
			}()),
		),
	)); err != nil {
		return nil, fmt.Errorf("unmarshal template: %w", err)
	}
	return p.convertTemplate(template), nil
}

func buildNodeRef(seq iter.Seq[string]) string {
	var sb strings.Builder
	for el := range seq {
		if _, err := strconv.Atoi(el); err == nil {
			sb.WriteString("[")
			sb.WriteString(el)
			sb.WriteString("]")
		} else {
			if sb.Len() > 0 {
				sb.WriteString(".")
			}
			sb.WriteString(el)
		}

	}
	return sb.String()
}

type MetadataReceiver interface {
	SetMetadata(types.Metadata)
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
		Location:   input.Loc,
		Properties: input.Properties,
		Resources:  children,
	}

	return resource
}
