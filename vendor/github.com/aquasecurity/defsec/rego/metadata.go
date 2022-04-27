package rego

import (
	"context"
	"fmt"

	"github.com/aquasecurity/defsec/providers"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/open-policy-agent/opa/rego"

	"github.com/open-policy-agent/opa/ast"
)

type StaticMetadata struct {
	ID                 string
	AVDID              string
	Type               string
	Title              string
	ShortCode          string
	Description        string
	Severity           string
	RecommendedActions string
	PrimaryURL         string
	References         []string
	InputOptions       InputOptions
	Package            string
}

type InputOptions struct {
	Combined  bool
	Selectors []Selector
}

type Selector struct {
	Type string
}

func (m StaticMetadata) ToRule() rules.Rule {

	provider := "generic"
	if len(m.InputOptions.Selectors) > 0 {
		provider = m.InputOptions.Selectors[0].Type
	}

	return rules.Rule{
		AVDID:       m.AVDID,
		LegacyID:    m.ID,
		ShortCode:   m.ShortCode,
		Summary:     m.Title,
		Explanation: m.Description,
		Impact:      "",
		Resolution:  m.RecommendedActions,
		Provider:    providers.Provider(provider),
		Service:     "general",
		Links:       m.References,
		Severity:    severity.Severity(m.Severity),
		RegoPackage: m.Package,
	}
}

type MetadataRetriever struct {
	compiler *ast.Compiler
}

func NewMetadataRetriever(compiler *ast.Compiler) *MetadataRetriever {
	return &MetadataRetriever{
		compiler: compiler,
	}
}

func (m *MetadataRetriever) RetrieveMetadata(ctx context.Context, module *ast.Module) (*StaticMetadata, error) {

	namespace := getModuleNamespace(module)
	metadataQuery := fmt.Sprintf("data.%s.__rego_metadata__", namespace)

	metadata := StaticMetadata{
		ID:           "N/A",
		Type:         "N/A",
		Title:        "N/A",
		Severity:     "UNKNOWN",
		Description:  fmt.Sprintf("Rego module: %s", module.Package.Path.String()),
		Package:      module.Package.Path.String(),
		InputOptions: m.queryInputOptions(ctx, module),
	}

	options := []func(*rego.Rego){
		rego.Query(metadataQuery),
		rego.Compiler(m.compiler),
	}
	instance := rego.New(options...)
	set, err := instance.Eval(ctx)
	if err != nil {
		return nil, err
	}

	// no metadata supplied
	if set == nil {
		return &metadata, nil
	}

	if len(set) != 1 {
		return nil, fmt.Errorf("failed to parse metadata: unexpected set length")
	}
	if len(set[0].Expressions) != 1 {
		return nil, fmt.Errorf("failed to parse metadata: unexpected expression length")
	}
	expression := set[0].Expressions[0]
	meta, ok := expression.Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to parse metadata: not an object")
	}

	if raw, ok := meta["id"]; ok {
		metadata.ID = fmt.Sprintf("%s", raw)
	}
	if raw, ok := meta["avd_id"]; ok {
		metadata.AVDID = fmt.Sprintf("%s", raw)
	}
	if raw, ok := meta["title"]; ok {
		metadata.Title = fmt.Sprintf("%s", raw)
	}
	if raw, ok := meta["short_code"]; ok {
		metadata.ShortCode = fmt.Sprintf("%s", raw)
	}
	if raw, ok := meta["severity"]; ok {
		metadata.Severity = fmt.Sprintf("%s", raw)
	}
	if raw, ok := meta["type"]; ok {
		metadata.Type = fmt.Sprintf("%s", raw)
	}
	if raw, ok := meta["description"]; ok {
		metadata.Description = fmt.Sprintf("%s", raw)
	}
	if raw, ok := meta["recommended_actions"]; ok {
		metadata.RecommendedActions = fmt.Sprintf("%s", raw)
	}
	if raw, ok := meta["url"]; ok {
		metadata.References = append(metadata.References, fmt.Sprintf("%s", raw))
	}

	return &metadata, nil
}

func (m *MetadataRetriever) queryInputOptions(ctx context.Context, module *ast.Module) InputOptions {

	options := InputOptions{
		Combined:  false,
		Selectors: nil,
	}

	namespace := getModuleNamespace(module)
	inputOptionQuery := fmt.Sprintf("data.%s.__rego_input__", namespace)
	instance := rego.New(
		rego.Query(inputOptionQuery),
		rego.Compiler(m.compiler),
	)
	set, err := instance.Eval(ctx)
	if err != nil {
		return options
	}

	if len(set) != 1 {
		return options
	}
	if len(set[0].Expressions) != 1 {
		return options
	}
	expression := set[0].Expressions[0]
	meta, ok := expression.Value.(map[string]interface{})
	if !ok {
		return options
	}

	if raw, ok := meta["combine"]; ok {
		if combine, ok := raw.(bool); ok {
			options.Combined = combine
		}
	}

	if raw, ok := meta["selector"]; ok {
		if each, ok := raw.([]interface{}); ok {
			for _, rawSelector := range each {
				var selector Selector
				if selectorMap, ok := rawSelector.(map[string]interface{}); ok {
					if rawType, ok := selectorMap["type"]; ok {
						selector.Type = fmt.Sprintf("%s", rawType)
					}
				}
				options.Selectors = append(options.Selectors, selector)
			}
		}
	}

	return options

}
