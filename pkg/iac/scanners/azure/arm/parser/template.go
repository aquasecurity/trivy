package parser

import (
	types2 "github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure/arm/parser/armjson"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

type Template struct {
	Metadata       types.Metadata          `json:"-"`
	Schema         types2.Value            `json:"$schema"`
	ContentVersion types2.Value            `json:"contentVersion"`
	APIProfile     types2.Value            `json:"apiProfile"`
	Parameters     map[string]Parameter    `json:"parameters"`
	Variables      map[string]types2.Value `json:"variables"`
	Functions      []Function              `json:"functions"`
	Resources      []Resource              `json:"resources"`
	Outputs        map[string]types2.Value `json:"outputs"`
}

type Parameter struct {
	Metadata     types.Metadata
	Type         types2.Value `json:"type"`
	DefaultValue types2.Value `json:"defaultValue"`
	MaxLength    types2.Value `json:"maxLength"`
	MinLength    types2.Value `json:"minLength"`
}

type Function struct{}

type Resource struct {
	Metadata types.Metadata `json:"-"`
	innerResource
}

func (t *Template) SetMetadata(m *types.Metadata) {
	t.Metadata = *m
}

func (r *Resource) SetMetadata(m *types.Metadata) {
	r.Metadata = *m
}

func (p *Parameter) SetMetadata(m *types.Metadata) {
	p.Metadata = *m
}

type innerResource struct {
	APIVersion types2.Value `json:"apiVersion"`
	Type       types2.Value `json:"type"`
	Kind       types2.Value `json:"kind"`
	Name       types2.Value `json:"name"`
	Location   types2.Value `json:"location"`
	Tags       types2.Value `json:"tags"`
	Sku        types2.Value `json:"sku"`
	Properties types2.Value `json:"properties"`
	Resources  []Resource   `json:"resources"`
}

func (v *Resource) UnmarshalJSONWithMetadata(node armjson.Node) error {

	if err := node.Decode(&v.innerResource); err != nil {
		return err
	}

	v.Metadata = node.Metadata()

	for _, comment := range node.Comments() {
		var str string
		if err := comment.Decode(&str); err != nil {
			return err
		}
		// TODO(someone): add support for metadata comments
		// v.Metadata.Comments = append(v.Metadata.Comments, str)
	}

	return nil
}
