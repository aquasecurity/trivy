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
	RootPath   string        `json:"root_path"`
	ModulePath string        `json:"module_path"`
	ParentPath string        `json:"parent_path"`
	Blocks     []BlockExport `json:"blocks"`
}

type BlockExport struct {
	Metadata   any                        `json:"__defsec_metadata"`
	Kind       string                     `json:"kind"`
	Type       string                     `json:"type"`
	Name       string                     `json:"name"`
	Attributes map[string]AttributeExport `json:"attributes"`
}

type AttributeExport struct {
	Metadata any             `json:"__defsec_metadata"`
	Name     string          `json:"name"`
	Value    json.RawMessage `json:"value"`
	Known    bool            `json:"known"`
}

func (m *Module) ToModuleExport() ModuleExport {
	var parentPath string
	if parentModule := m.Parent(); parentModule != nil {
		parentPath = parentModule.ModulePath()
	}
	return ModuleExport{
		RootPath:   m.RootPath(),
		ModulePath: m.ModulePath(),
		ParentPath: parentPath,
		Blocks: lo.Map(m.blocks, func(b *Block, _ int) BlockExport {
			return b.ToBlockExport()
		}),
	}
}

func (b *Block) ToBlockExport() BlockExport {
	typeLabel := b.TypeLabel()
	nameLabel := b.NameLabel()

	if len(b.Labels()) == 1 {
		nameLabel = typeLabel
		typeLabel = ""
	}

	return BlockExport{
		Metadata: b.metadata.ToRego(),
		Kind:     b.Type(),
		Type:     typeLabel,
		Name:     nameLabel,
		Attributes: lo.SliceToMap(
			b.attributes, func(a *Attribute) (string, AttributeExport) {
				return a.Name(), a.ToAttributeExport()
			},
		),
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
