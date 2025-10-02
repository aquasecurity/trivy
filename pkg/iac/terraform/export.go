package terraform

import (
	"encoding/json"

	"github.com/samber/lo"
	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"

	"github.com/aquasecurity/trivy/pkg/log"
)

func ExportModules(modules Modules) TerraformConfigExport {
	return TerraformConfigExport{
		Modules: lo.Map(modules, func(m *Module, _ int) ModuleExport {
			return m.ToModuleExport()
		}),
	}
}

// TODO(nikpivkin): export directly to OPA values
type TerraformConfigExport struct {
	Modules []ModuleExport `json:"modules"`
}

type ModuleExport struct {
	RootPath   string                `json:"root_path"`
	ModulePath string                `json:"module_path"`
	ParentPath string                `json:"parent_path"`
	Blocks     []TopLevelBlockExport `json:"blocks"`
}

type TopLevelBlockExport struct {
	Kind string `json:"kind"`
	Type string `json:"type"`
	BlockExport
}

type AttributeExport struct {
	Metadata any             `json:"__defsec_metadata"`
	Name     string          `json:"name"`
	Value    json.RawMessage `json:"value"`
	Known    bool            `json:"known"`
}

type BlockExport struct {
	Metadata   any                        `json:"__defsec_metadata"`
	Name       string                     `json:"name"`
	Attributes map[string]AttributeExport `json:"attributes"`
	Children   []BlockExport              `json:"children"`
}

func (c *Module) ToModuleExport() ModuleExport {
	var parentPath string
	if parentModule := c.Parent(); parentModule != nil {
		parentPath = parentModule.ModulePath()
	}
	return ModuleExport{
		RootPath:   c.RootPath(),
		ModulePath: c.ModulePath(),
		ParentPath: parentPath,
		Blocks: lo.Map(c.blocks, func(b *Block, _ int) TopLevelBlockExport {
			return b.ToTopLevelBlockExport()
		}),
	}
}

func (b *Block) ToTopLevelBlockExport() TopLevelBlockExport {
	return TopLevelBlockExport{
		Kind:        b.Type(),
		Type:        b.TypeLabel(),
		BlockExport: b.ToBlockExport(),
	}
}

func (b *Block) ToBlockExport() BlockExport {
	nameLabel := b.NameLabel()

	if len(b.Labels()) == 0 {
		nameLabel = b.Type()
	}

	return BlockExport{
		Name:     nameLabel,
		Metadata: b.metadata.ToRego(),
		Attributes: lo.SliceToMap(b.attributes, func(a *Attribute) (string, AttributeExport) {
			return a.Name(), a.ToAttributeExport()
		}),
		Children: lo.FilterMap(b.childBlocks, func(b *Block, _ int) (BlockExport, bool) {
			return b.ToBlockExport(), len(b.Labels()) == 0
		}),
	}
}

func (a *Attribute) ToAttributeExport() AttributeExport {
	value, known := ExportCtyValueToJSON(a.Value())
	return AttributeExport{
		Metadata: a.metadata.ToRego(),
		Name:     a.Name(),
		Known:    known,
		Value:    value,
	}
}

func ExportCtyValueToJSON(v cty.Value) (json.RawMessage, bool) {
	if v.IsNull() || !v.IsKnown() {
		return json.RawMessage("null"), false
	}

	ty := v.Type()
	bytes, err := ctyjson.Marshal(v, ty)
	if err != nil {
		log.WithPrefix("terraform").Debug("Failed to marshal cty value",
			log.String("value", v.GoString()), log.Err(err))
		return json.RawMessage("null"), false
	}

	return json.RawMessage(bytes), true
}
