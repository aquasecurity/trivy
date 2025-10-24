package parser

import (
	"crypto/md5" //#nosec
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/mapfs"
)

type Parser struct {
	logger *log.Logger
}

func New() *Parser {
	return &Parser{
		logger: log.WithPrefix("tfjson parser"),
	}
}

func (p *Parser) ParseFile(filepath string) (*PlanFile, error) {

	if _, err := os.Stat(filepath); err != nil {
		return nil, err
	}

	reader, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return p.Parse(reader)
}

func (p *Parser) Parse(reader io.Reader) (*PlanFile, error) {

	var planFile PlanFile

	if err := json.NewDecoder(reader).Decode(&planFile); err != nil {
		return nil, err
	}

	return &planFile, nil

}

func (p *PlanFile) ToFS() (fs.FS, error) {
	resources, err := getResources(p.PlannedValues.RootModule, p.ResourceChanges, p.Configuration)
	if err != nil {
		return nil, err
	}

	fileResources := make([]string, 0, len(resources))
	for _, r := range resources {
		fileResources = append(fileResources, r.ToHCL())
	}
	fileContent := strings.Join(fileResources, "\n\n")

	rootFS := mapfs.New()
	if err := rootFS.WriteVirtualFile("main.tf", []byte(fileContent), os.ModePerm); err != nil {
		return nil, err
	}
	return rootFS, nil

}

func getResources(module Module, resourceChanges []ResourceChange, configuration Configuration) ([]terraform.PlanBlock, error) {
	var resources []terraform.PlanBlock
	for _, r := range module.Resources {
		resourceName := r.Name
		if strings.HasPrefix(r.Address, "module.") {
			hashable := strings.TrimSuffix(strings.Split(r.Address, fmt.Sprintf(".%s.", r.Type))[0], ".data")
			/* #nosec */
			hash := fmt.Sprintf("%x", md5.Sum([]byte(hashable)))
			resourceName = fmt.Sprintf("%s_%s", r.Name, hash)
		}

		resourceConfig := getConfiguration(r.Address, configuration.RootModule)
		schema := make(BlockSchema)
		if resourceConfig != nil {
			schema = schemaForBlock(r, resourceConfig.Expressions)
		}

		changes := getValues(r.Address, resourceChanges)
		resource := decodeBlock(schema, changes.After)
		// fill top-level block fileds
		resource.BlockType = lo.Ternary(r.Mode == "managed", "resource", r.Mode)
		resource.Type = r.Type
		resource.Name = resourceName
		resources = append(resources, resource)
	}

	for _, m := range module.ChildModules {
		cr, err := getResources(m.Module, resourceChanges, configuration)
		if err != nil {
			return nil, err
		}
		resources = append(resources, cr...)
	}

	return resources, nil
}

func decodeBlock(schema BlockSchema, rawBlock map[string]any) terraform.PlanBlock {
	block := terraform.PlanBlock{
		Attributes: make(map[string]any),
	}

	for k, child := range rawBlock {
		childSchema := schema[k]
		switch t := child.(type) {
		case []any:
			if childSchema != nil {
				switch childSchema.Type {
				case Attribute:
					block.Attributes[k] = decodeAttribute(childSchema, child)
				case Block:
					nestedBlocks := decodeNestedBlocks(childSchema, k, t)
					block.Blocks = append(block.Blocks, nestedBlocks...)
				}
			} else {
				// just attribute
				block.Attributes[k] = t
			}
		default:
			if childSchema != nil {
				switch childSchema.Type {
				case Attribute:
					block.Attributes[k] = decodeAttribute(childSchema, child)
				case Block:
					nestedBlocks := decodeNestedBlocks(childSchema, k, []any{child})
					block.Blocks = append(block.Blocks, nestedBlocks...)
				}
			} else {
				block.Attributes[k] = child
			}
		}
	}
	return block
}

func decodeNestedBlocks(schema *SchemaNode, name string, v []any) []terraform.PlanBlock {
	nestedBlocks := make([]terraform.PlanBlock, 0, len(v))
	for i, el := range v {
		m, ok := el.(map[string]any)
		if !ok {
			continue
		}
		nestedBlockSchema := make(BlockSchema)
		if i < len(schema.Children) {
			nestedBlockSchema = schema.Children[i]
		}
		nestedBlock := decodeBlock(nestedBlockSchema, m)
		nestedBlock.Name = name
		nestedBlocks = append(nestedBlocks, nestedBlock)
	}
	return nestedBlocks
}

func decodeAttribute(schema *SchemaNode, rawAttr any) any {
	if schema.Value == nil {
		return rawAttr
	}

	return rawAttr
	// TODO: For attributes of type object or map, the schema does not include field names and looks like:
	// "list_attr": { "references": ["local.foo"] },
	// Therefore, we cannot determine which specific fields are unknown.
	// return resolveAttribute(rawAttr, schema.Value)
}

func resolveAttribute(known, config any) any {
	switch v := known.(type) {
	case []any:
		return v
	case map[string]any:
		cm, ok := config.(map[string]any)
		if !ok {
			return v
		}

		result := make(map[string]any)
		for k, cv := range cm {
			if vv, exists := result[k]; exists {
				result[k] = resolveAttribute(vv, cv)
			} else {
				result[k] = cv
			}
		}
		return result
	default:
		return known
	}
}

func unpackConfigurationValue(val any, r Resource) (any, bool) {
	if t, ok := val.(map[string]any); ok {
		for k, v := range t {
			switch k {
			case "references":
				reference := v.([]any)[0].(string)
				if strings.HasPrefix(r.Address, "module.") {
					hashable := strings.TrimSuffix(strings.Split(r.Address, fmt.Sprintf(".%s.", r.Type))[0], ".data")
					/* #nosec */
					hash := fmt.Sprintf("%x", md5.Sum([]byte(hashable)))

					parts := strings.Split(reference, ".")
					var rejoin []string

					name := parts[1]
					remainder := parts[2:]
					if parts[0] == "data" {
						rejoin = append(rejoin, parts[:2]...)
						name = parts[2]
						remainder = parts[3:]
					} else {
						rejoin = append(rejoin, parts[:1]...)
					}

					rejoin = append(rejoin, fmt.Sprintf("%s_%s", name, hash))
					rejoin = append(rejoin, remainder...)

					reference = strings.Join(rejoin, ".")
				}
				return terraform.PlanReference{Value: reference}, false
			case "constant_value":
				return v, false
			}
		}
	}

	return nil, false
}

func getConfiguration(address string, configuration ConfigurationModule) *ConfigurationResource {

	workingAddress := address
	var moduleParts []string
	for strings.HasPrefix(workingAddress, "module.") {
		workingAddressParts := strings.Split(workingAddress, ".")
		moduleParts = append(moduleParts, workingAddressParts[1])
		workingAddress = strings.Join(workingAddressParts[2:], ".")
	}

	workingModule := configuration
	for _, moduleName := range moduleParts {
		if module, ok := workingModule.ModuleCalls[moduleName]; ok {
			workingModule = module.Module
		}
	}

	for _, resource := range workingModule.Resources {
		if resource.Address == workingAddress {
			return &resource
		}
	}

	return nil
}

func getValues(address string, resourceChange []ResourceChange) *ResourceChange {
	for _, r := range resourceChange {
		if r.Address == address {
			return &r
		}
	}
	return nil
}

type NodeType = int

const (
	Attribute NodeType = iota
	Block
)

type BlockSchema = map[string]*SchemaNode

type SchemaNode struct {
	Type     NodeType
	Children []BlockSchema // only for blocks
	Value    any           // only for attributes, maybe null
}

func schemaForBlock(r Resource, expressions map[string]any) BlockSchema {
	schema := make(map[string]*SchemaNode)
	for n, expr := range expressions {
		nodeSchema := schemaForExpression(r, expr)
		if nodeSchema != nil {
			schema[n] = nodeSchema
		}
	}
	return schema
}

func schemaForExpression(r Resource, expr any) *SchemaNode {
	switch v := expr.(type) {
	case map[string]any:
		attrKeys := []string{"constant_value", "references"}
		for _, k := range attrKeys {
			if _, exists := v[k]; exists {
				attrVal, _ := unpackConfigurationValue(v, r)
				return &SchemaNode{
					Type:  Attribute,
					Value: attrVal,
				}
			}
		}
		return &SchemaNode{
			Type:     Block,
			Children: []BlockSchema{schemaForBlock(r, v)},
		}
	case []any:
		children := make([]BlockSchema, 0, len(v))
		for _, el := range v {
			if m, ok := el.(map[string]any); ok {
				children = append(children, schemaForBlock(r, m))
			}
		}
		return &SchemaNode{
			Type:     Block,
			Children: children,
		}
	}

	return nil
}
