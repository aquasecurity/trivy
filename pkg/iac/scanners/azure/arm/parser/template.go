package parser

import (
	"bytes"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"iter"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure/resolver"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

type MetadataReceiver interface {
	SetMetadata(*types.Metadata)
}

type Template struct {
	Metadata       *types.Metadata        `json:"-"`
	Schema         azure.Value            `json:"$schema"`
	ContentVersion azure.Value            `json:"contentVersion"`
	APIProfile     azure.Value            `json:"apiProfile"`
	Parameters     map[string]Parameter   `json:"parameters"`
	Variables      map[string]azure.Value `json:"variables"`
	Functions      []Function             `json:"functions"`
	Resources      []Resource             `json:"resources"`
	Outputs        map[string]azure.Value `json:"outputs"`
}

type Parameter struct {
	Metadata     *types.Metadata
	Type         azure.Value `json:"type"`
	DefaultValue azure.Value `json:"defaultValue"`
	MaxLength    azure.Value `json:"maxLength"`
	MinLength    azure.Value `json:"minLength"`
}

type Function struct{}

type Resource struct {
	Metadata *types.Metadata `json:"-"`
	innerResource
}

func (t *Template) SetMetadata(m *types.Metadata) {
	t.Metadata = m
}

func (r *Resource) SetMetadata(m *types.Metadata) {
	r.Metadata = m
}

func (p *Parameter) SetMetadata(m *types.Metadata) {
	p.Metadata = m
}

type innerResource struct {
	APIVersion azure.Value `json:"apiVersion"`
	Type       azure.Value `json:"type"`
	Kind       azure.Value `json:"kind"`
	Name       azure.Value `json:"name"`
	Location   azure.Value `json:"location"`
	Tags       azure.Value `json:"tags"`
	Sku        azure.Value `json:"sku"`
	Properties azure.Value `json:"properties"`
	Resources  []Resource  `json:"resources"`
}

func ParseTemplate(fsys fs.FS, path string) (*Template, error) {
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	lr := xjson.NewLineReader(bytes.NewReader(xjson.ToRFC8259(data)))

	mc := metadataCollector{
		path:    path,
		fsys:    fsys,
		entries: make(map[jsontext.Pointer]*types.Metadata),
	}

	// First, check if resources is a dictionary or array
	var rawTemplate struct {
		Resources any `json:"resources"`
	}

	if err := json.UnmarshalRead(lr, &rawTemplate); err != nil {
		return nil, fmt.Errorf("unmarshal template: %w", err)
	}

	// Reset the reader for full parsing
	lr = xjson.NewLineReader(bytes.NewReader(xjson.ToRFC8259(data)))

	// Check if resources is a dictionary (Bicep modules)
	if resourcesMap, ok := rawTemplate.Resources.(map[string]any); ok && len(resourcesMap) > 0 {
		// Handle dictionary resources (Bicep modules) - parse the full template manually
		var rawFullTemplate struct {
			Schema         azure.Value            `json:"$schema"`
			ContentVersion azure.Value            `json:"contentVersion"`
			APIProfile     azure.Value            `json:"apiProfile"`
			Parameters     map[string]Parameter   `json:"parameters"`
			Variables      map[string]azure.Value `json:"variables"`
			Functions      []Function             `json:"functions"`
			Resources      map[string]any         `json:"resources"`
			Outputs        map[string]azure.Value `json:"outputs"`
		}

		if err := json.UnmarshalRead(lr, &rawFullTemplate, json.WithUnmarshalers(
			xjson.UnmarshalerWithLocation[MetadataReceiver](lr, func() xjson.DecodeHook {
				return xjson.DecodeHook{
					After: mc.After,
				}
			}()),
		)); err != nil {
			return nil, fmt.Errorf("unmarshal template: %w", err)
		}

		// Convert dictionary resources to array
		var resources []Resource
		for name, resourceData := range rawFullTemplate.Resources {
			if resourceMap, ok := resourceData.(map[string]any); ok {
				resource := convertMapToResource(resourceMap, 0)
				// Set the name from the dictionary key if not already set
				if resource.Name.Raw() == nil {
					resource.Name = azure.NewValue(name, types.NewMetadata(
						types.NewRange(path, 0, 0, "", fsys),
						"",
					))
				}
				resources = append(resources, resource)
			}
		}

		// Create the final template
		rootMetadata := types.NewMetadata(
			types.NewRange(path, 0, 0, "", fsys),
			"",
		).WithInternal(resolver.NewResolver())

		template := Template{
			Metadata:       &rootMetadata,
			Schema:         rawFullTemplate.Schema,
			ContentVersion: rawFullTemplate.ContentVersion,
			APIProfile:     rawFullTemplate.APIProfile,
			Parameters:     rawFullTemplate.Parameters,
			Variables:      rawFullTemplate.Variables,
			Functions:      rawFullTemplate.Functions,
			Resources:      resources,
			Outputs:        rawFullTemplate.Outputs,
		}

		mc.linkParentMetadata()
		return &template, nil
	}

	// Handle array resources (standard ARM templates)
	var template Template
	if err := json.UnmarshalRead(lr, &template, json.WithUnmarshalers(
		xjson.UnmarshalerWithLocation[MetadataReceiver](lr, func() xjson.DecodeHook {
			return xjson.DecodeHook{
				After: mc.After,
			}
		}()),
	)); err != nil {
		return nil, fmt.Errorf("unmarshal template: %w", err)
	}
	mc.linkParentMetadata()

	rootMetadata := types.NewMetadata(
		types.NewRange(path, 0, 0, "", fsys),
		"",
	).WithInternal(resolver.NewResolver())
	template.Metadata.SetParentPtr(&rootMetadata)
	return &template, nil
}

type metadataCollector struct {
	path    string
	fsys    fs.FS
	entries map[jsontext.Pointer]*types.Metadata
}

func (c *metadataCollector) After(dec *jsontext.Decoder, obj any, loc ftypes.Location) {
	ptr := dec.StackPointer()
	ref := buildNodeRef(ptr.Tokens())
	rng := types.NewRange(c.path, loc.StartLine, loc.EndLine, "", c.fsys)

	md := types.NewMetadata(rng, ref)
	c.entries[ptr] = &md

	if r, ok := obj.(MetadataReceiver); ok {
		r.SetMetadata(&md)
	}
}

func (c *metadataCollector) linkParentMetadata() {
	for path, md := range c.entries {
		if md == nil || !isValidMetadata(md) {
			continue
		}
		parentPath, ok := c.findClosestValidParent(path)
		if !ok || parentPath == path {
			continue
		}
		md.SetParentPtr(c.entries[parentPath])
	}
}

func (c *metadataCollector) findClosestValidParent(path jsontext.Pointer) (jsontext.Pointer, bool) {
	for {
		path = path.Parent()
		if md, ok := c.entries[path]; ok && md != nil && isValidMetadata(md) {
			return path, true
		}
		if path == "" {
			return "", false
		}
	}
}

func convertMapToResource(resourceMap map[string]any, _ int) Resource {
	// Create a basic resource with metadata
	metadata := types.NewMetadata(
		types.NewRange("", 0, 0, "", nil),
		"",
	)

	resource := Resource{
		Metadata: &metadata,
		innerResource: innerResource{
			APIVersion: convertToAzureValue(resourceMap["apiVersion"]),
			Type:       convertToAzureValue(resourceMap["type"]),
			Kind:       convertToAzureValue(resourceMap["kind"]),
			Name:       convertToAzureValue(resourceMap["name"]),
			Location:   convertToAzureValue(resourceMap["location"]),
			Tags:       convertToAzureValue(resourceMap["tags"]),
			Sku:        convertToAzureValue(resourceMap["sku"]),
			Properties: convertToAzureValue(resourceMap["properties"]),
			Resources:  []Resource{}, // Will be populated if needed
		},
	}

	// Handle nested resources if they exist
	if nestedResources, ok := resourceMap["resources"].([]any); ok {
		for i, nestedResourceData := range nestedResources {
			if nestedResourceMap, ok := nestedResourceData.(map[string]any); ok {
				nestedResource := convertMapToResource(nestedResourceMap, i)
				resource.Resources = append(resource.Resources, nestedResource)
			}
		}
	}

	return resource
}

func convertToAzureValue(value any) azure.Value {
	if value == nil {
		return azure.Value{}
	}

	metadata := types.NewMetadata(
		types.NewRange("", 0, 0, "", nil),
		"",
	)

	return azure.NewValue(value, metadata)
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

func isValidMetadata(m *types.Metadata) bool {
	rng := m.Range()
	return rng.GetStartLine() != 0 && rng.GetEndLine() != 0
}
