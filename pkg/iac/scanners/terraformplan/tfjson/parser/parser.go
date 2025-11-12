package parser

import (
	"crypto/md5" //#nosec
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/mapfs"
)

const TerraformMainFile = "main.tf"

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
	resources, err := buildPlanBlocks(p.PlannedValues.RootModule, p.ResourceChanges, p.Configuration)
	if err != nil {
		return nil, err
	}

	fileResources := make([]string, 0, len(resources))
	for _, r := range resources {
		fileResources = append(fileResources, r.ToHCL())
	}
	fileContent := strings.Join(fileResources, "\n")

	rootFS := mapfs.New()
	if err := rootFS.WriteVirtualFile(TerraformMainFile, []byte(fileContent), os.ModePerm); err != nil {
		return nil, err
	}
	return rootFS, nil
}

func buildPlanBlocks(module Module, resourceChanges []ResourceChange, configuration Configuration) ([]*terraform.PlanBlock, error) {
	var resources []*terraform.PlanBlock
	for _, r := range module.Resources {
		resourceExprs := getConfiguration(r.Address, configuration.RootModule)
		schema := schemaForBlock(r, resourceExprs)
		changes := getValues(r.Address, resourceChanges)
		resource := decodeBlock(schema, changes.After)
		// fill top-level block fileds
		resource.BlockType = r.BlockType()
		resource.Type = r.Type
		resource.Name = moduleResourceName(r.Address, r.Type, r.Name)
		resources = append(resources, resource)
	}

	for _, m := range module.ChildModules {
		cr, err := buildPlanBlocks(m.Module, resourceChanges, configuration)
		if err != nil {
			return nil, err
		}
		resources = append(resources, cr...)
	}

	return resources, nil
}

func decodeBlock(schema BlockSchema, rawBlock map[string]any) *terraform.PlanBlock {
	block := &terraform.PlanBlock{
		Attributes: make(map[string]any),
	}

	for k, child := range rawBlock {
		handleChild(block, k, child, schema[k])
	}

	populateReferences(schema, block)
	return block
}

func handleChild(block *terraform.PlanBlock, k string, child any, schema *SchemaNode) {
	switch {
	case schema == nil:
		appendBlockOrAttribute(block, k, child)
	case schema.Type == AttributeNode:
		appendBlockOrAttribute(block, k, decodeAttribute(schema, child))
	case schema.Type == BlockNode:
		nestedBlocks := decodeNestedBlocks(schema, k, normalizeToSlice(child))
		block.Blocks = append(block.Blocks, nestedBlocks...)
	}
}

func normalizeToSlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return []any{v}
}

func appendBlockOrAttribute(block *terraform.PlanBlock, name string, value any) {
	if s, ok := value.([]any); ok && len(s) > 0 {
		if m, ok := s[0].(map[string]any); ok {
			block.Blocks = append(block.Blocks, &terraform.PlanBlock{
				Name:       name,
				Attributes: m,
			})
			return
		}
	}
	block.Attributes[name] = value
}

func populateReferences(schema BlockSchema, block *terraform.PlanBlock) {
	for k, childNodeSchema := range schema {
		switch childNodeSchema.Type {
		case BlockNode:
			cb := block.GetOrCreateBlock(k)
			for _, childrenBlockChema := range childNodeSchema.Children {
				populateReferences(childrenBlockChema, cb)
			}
		case AttributeNode:
			if ref, ok := childNodeSchema.Value.(terraform.PlanReference); ok {
				if _, exists := block.Attributes[k]; !exists {
					block.Attributes[k] = ref
				}
			}
		}
	}
}

func decodeNestedBlocks(schema *SchemaNode, name string, v []any) []*terraform.PlanBlock {
	nestedBlocks := make([]*terraform.PlanBlock, 0, len(v))
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

	// For attributes of type object or map, the schema does not include field names and looks like:
	// "list_attr": { "references": ["local.foo"] },
	// Therefore, we cannot determine which specific fields are unknown
	// and we can ignore references from expressions.
	return rawAttr
}

func unpackConfigurationValue(val map[string]any, r Resource) any {
	for k, v := range val {
		switch k {
		case "references":
			s, ok := v.([]any)
			if !ok || len(s) == 0 {
				return terraform.PlanReference{}
			}

			ref, ok := s[0].(string)
			if !ok {
				return terraform.PlanReference{}
			}
			return parseAttributeReference(r.Address, r.Type, ref)
		case "constant_value":
			return v
		}
	}

	return nil
}

// parseAttributeReference parses an attribute reference string and returns
// a PlanReference. The reference may point to another resource and is adjusted
// according to Terraform address rules.
func parseAttributeReference(rAddress, rType, reference string) terraform.PlanReference {
	parts := strings.Split(reference, ".")
	nameIdx := 1
	if parts[0] == "data" {
		nameIdx = 2
	}
	parts[nameIdx] = moduleResourceName(rAddress, rType, parts[nameIdx])
	reference = strings.Join(parts, ".")
	return terraform.PlanReference{Value: reference}
}

// moduleResourceName returns the resource name with a module hash if the resource
// is inside a Terraform module. Otherwise, it returns the original name.
func moduleResourceName(rAddress, rType, name string) string {
	if !strings.HasPrefix(rAddress, "module.") {
		return name
	}

	hashable := strings.TrimSuffix(strings.Split(rAddress, fmt.Sprintf(".%s.", rType))[0], ".data")
	/* #nosec */
	hash := fmt.Sprintf("%x", md5.Sum([]byte(hashable)))
	return fmt.Sprintf("%s_%s", name, hash)
}

func getConfiguration(address string, configuration ConfigurationModule) ResourceExpressions {
	moduleParts, resourceAddress := splitModuleAddress(address)

	for _, moduleName := range moduleParts {
		if module, ok := configuration.ModuleCalls[moduleName]; ok {
			configuration = module.Module
		}
	}

	for _, resource := range configuration.Resources {
		if resource.Address == resourceAddress {
			return resource.Expressions
		}
	}

	return make(ResourceExpressions)
}

// splitModuleAddress splits a Terraform address into module parts and the final resource address.
// For example: "module.network.module.subnet.aws_subnet.this[0]" =>
// moduleParts: ["network", "subnet"], resourceAddress: "aws_subnet.this[0]"
func splitModuleAddress(address string) (moduleParts []string, resourceAddress string) {
	resourceAddress = address
	for strings.HasPrefix(resourceAddress, "module.") {
		parts := strings.Split(resourceAddress, ".")
		if len(parts) > 3 {
			moduleParts = append(moduleParts, parts[1])
			resourceAddress = strings.Join(parts[2:], ".")
		} else {
			break
		}
	}
	return
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
	AttributeNode NodeType = iota
	BlockNode
)

type BlockSchema = map[string]*SchemaNode

// SchemaNode represents a node in the Terraform resource schema.
type SchemaNode struct {
	// Type specifies whether the node is a Block or an Attribute.
	Type NodeType

	// Only used for Block nodes, contains nested BlockSchemas.
	Children []BlockSchema

	// Only used for Attribute nodes.
	// Can be nil, a raw Go value (number, bool, string), or a PlanReference
	// if the attribute refers to another resource.
	Value any
}

func schemaForBlock(r Resource, expressions ResourceExpressions) BlockSchema {
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
				attrVal := unpackConfigurationValue(v, r)
				return &SchemaNode{
					Type:  AttributeNode,
					Value: attrVal,
				}
			}
		}
		return &SchemaNode{
			Type:     BlockNode,
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
			Type:     BlockNode,
			Children: children,
		}
	}

	return nil
}
