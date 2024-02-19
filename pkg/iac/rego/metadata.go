package rego

import (
	"context"
	"fmt"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"

	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type StaticMetadata struct {
	ID                 string
	AVDID              string
	Title              string
	ShortCode          string
	Aliases            []string
	Description        string
	Severity           string
	RecommendedActions string
	PrimaryURL         string
	References         []string
	InputOptions       InputOptions
	Package            string
	Frameworks         map[framework.Framework][]string
	Provider           string
	Service            string
	Library            bool
	CloudFormation     *scan.EngineMetadata
	Terraform          *scan.EngineMetadata
}

func NewStaticMetadata(pkgPath string, inputOpt InputOptions) *StaticMetadata {
	return &StaticMetadata{
		ID:           "N/A",
		Title:        "N/A",
		Severity:     "UNKNOWN",
		Description:  fmt.Sprintf("Rego module: %s", pkgPath),
		Package:      pkgPath,
		InputOptions: inputOpt,
		Frameworks:   make(map[framework.Framework][]string),
	}
}

func (sm *StaticMetadata) Update(meta map[string]any) error {

	upd := func(field *string, key string) {
		if raw, ok := meta[key]; ok {
			*field = fmt.Sprintf("%s", raw)
		}
	}

	upd(&sm.ID, "id")
	upd(&sm.AVDID, "avd_id")
	upd(&sm.Title, "title")
	upd(&sm.ShortCode, "short_code")
	upd(&sm.Description, "description")
	upd(&sm.Service, "service")
	upd(&sm.Provider, "provider")
	upd(&sm.RecommendedActions, "recommended_actions")
	upd(&sm.RecommendedActions, "recommended_action")

	if raw, ok := meta["severity"]; ok {
		sm.Severity = strings.ToUpper(fmt.Sprintf("%s", raw))
	}

	if raw, ok := meta["library"]; ok {
		if lib, ok := raw.(bool); ok {
			sm.Library = lib
		}
	}

	if raw, ok := meta["url"]; ok {
		sm.References = append(sm.References, fmt.Sprintf("%s", raw))
	}
	if raw, ok := meta["frameworks"]; ok {
		frameworks, ok := raw.(map[string][]string)
		if !ok {
			return fmt.Errorf("failed to parse framework metadata: not an object")
		}
		for fw, sections := range frameworks {
			sm.Frameworks[framework.Framework(fw)] = sections
		}
	}
	if raw, ok := meta["related_resources"]; ok {
		switch relatedResources := raw.(type) {
		case []map[string]any:
			for _, relatedResource := range relatedResources {
				if raw, ok := relatedResource["ref"]; ok {
					sm.References = append(sm.References, fmt.Sprintf("%s", raw))
				}
			}
		case []string:
			sm.References = append(sm.References, relatedResources...)
		}
	}

	sm.updateAliases(meta)

	var err error
	if sm.CloudFormation, err = NewEngineMetadata("cloud_formation", meta); err != nil {
		return err
	}

	if sm.Terraform, err = NewEngineMetadata("terraform", meta); err != nil {
		return err
	}

	return nil
}

func (sm *StaticMetadata) updateAliases(meta map[string]any) {
	if raw, ok := meta["aliases"]; ok {
		if aliases, ok := raw.([]interface{}); ok {
			for _, a := range aliases {
				sm.Aliases = append(sm.Aliases, fmt.Sprintf("%s", a))
			}
		}
	}
}

func (sm *StaticMetadata) FromAnnotations(annotations *ast.Annotations) error {
	sm.Title = annotations.Title
	sm.Description = annotations.Description
	for _, resource := range annotations.RelatedResources {
		if !resource.Ref.IsAbs() {
			continue
		}
		sm.References = append(sm.References, resource.Ref.String())
	}
	if custom := annotations.Custom; custom != nil {
		if err := sm.Update(custom); err != nil {
			return err
		}
	}
	if len(annotations.RelatedResources) > 0 {
		sm.PrimaryURL = annotations.RelatedResources[0].Ref.String()
	}
	return nil
}

func NewEngineMetadata(schema string, meta map[string]interface{}) (*scan.EngineMetadata, error) {
	var sMap map[string]interface{}
	if raw, ok := meta[schema]; ok {
		sMap, ok = raw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("failed to parse %s metadata: not an object", schema)
		}
	}

	var em scan.EngineMetadata
	if val, ok := sMap["good_examples"].(string); ok {
		em.GoodExamples = []string{val}
	}
	if val, ok := sMap["bad_examples"].(string); ok {
		em.BadExamples = []string{val}
	}
	if val, ok := sMap["links"].(string); ok {
		em.Links = []string{val}
	}
	if val, ok := sMap["remediation_markdown"].(string); ok {
		em.RemediationMarkdown = val
	}

	return &em, nil
}

type InputOptions struct {
	Combined  bool
	Selectors []Selector
}

type Selector struct {
	Type     string
	Subtypes []SubType
}

type SubType struct {
	Group     string
	Version   string
	Kind      string
	Namespace string
	Service   string // only for cloud
	Provider  string // only for cloud
}

func (m StaticMetadata) ToRule() scan.Rule {

	provider := "generic"
	if m.Provider != "" {
		provider = m.Provider
	} else if len(m.InputOptions.Selectors) > 0 {
		provider = m.InputOptions.Selectors[0].Type
	}
	service := "general"
	if m.Service != "" {
		service = m.Service
	}

	return scan.Rule{
		AVDID:          m.AVDID,
		Aliases:        append(m.Aliases, m.ID),
		ShortCode:      m.ShortCode,
		Summary:        m.Title,
		Explanation:    m.Description,
		Impact:         "",
		Resolution:     m.RecommendedActions,
		Provider:       providers.Provider(provider),
		Service:        service,
		Links:          m.References,
		Severity:       severity.Severity(m.Severity),
		RegoPackage:    m.Package,
		Frameworks:     m.Frameworks,
		CloudFormation: m.CloudFormation,
		Terraform:      m.Terraform,
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

func (m *MetadataRetriever) findPackageAnnotations(module *ast.Module) *ast.Annotations {
	annotationSet := m.compiler.GetAnnotationSet()
	if annotationSet == nil {
		return nil
	}
	for _, annotation := range annotationSet.Flatten() {
		if annotation.GetPackage().Path.String() != module.Package.Path.String() || annotation.Annotations.Scope != "package" {
			continue
		}
		return annotation.Annotations
	}
	return nil
}

func (m *MetadataRetriever) RetrieveMetadata(ctx context.Context, module *ast.Module, contents ...any) (*StaticMetadata, error) {

	metadata := NewStaticMetadata(
		module.Package.Path.String(),
		m.queryInputOptions(ctx, module),
	)

	// read metadata from official rego annotations if possible
	if annotations := m.findPackageAnnotations(module); annotations != nil {
		if err := metadata.FromAnnotations(annotations); err != nil {
			return nil, err
		}
		return metadata, nil
	}

	// otherwise, try to read metadata from the rego module itself - we used to do this before annotations were a thing
	namespace := getModuleNamespace(module)
	metadataQuery := fmt.Sprintf("data.%s.__rego_metadata__", namespace)

	options := []func(*rego.Rego){
		rego.Query(metadataQuery),
		rego.Compiler(m.compiler),
		rego.Capabilities(nil),
	}
	// support dynamic metadata fields
	for _, in := range contents {
		options = append(options, rego.Input(in))
	}

	instance := rego.New(options...)
	set, err := instance.Eval(ctx)
	if err != nil {
		return nil, err
	}

	// no metadata supplied
	if set == nil {
		return metadata, nil
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

	if err := metadata.Update(meta); err != nil {
		return nil, err
	}

	return metadata, nil
}

// nolint: gocyclo
func (m *MetadataRetriever) queryInputOptions(ctx context.Context, module *ast.Module) InputOptions {

	options := InputOptions{
		Combined:  false,
		Selectors: nil,
	}

	var metadata map[string]interface{}

	// read metadata from official rego annotations if possible
	if annotation := m.findPackageAnnotations(module); annotation != nil && annotation.Custom != nil {
		if input, ok := annotation.Custom["input"]; ok {
			if mapped, ok := input.(map[string]interface{}); ok {
				metadata = mapped
			}
		}
	}

	if metadata == nil {

		namespace := getModuleNamespace(module)
		inputOptionQuery := fmt.Sprintf("data.%s.__rego_input__", namespace)
		instance := rego.New(
			rego.Query(inputOptionQuery),
			rego.Compiler(m.compiler),
			rego.Capabilities(nil),
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
		metadata = meta
	}

	if raw, ok := metadata["combine"]; ok {
		if combine, ok := raw.(bool); ok {
			options.Combined = combine
		}
	}

	if raw, ok := metadata["selector"]; ok {
		if each, ok := raw.([]interface{}); ok {
			for _, rawSelector := range each {
				var selector Selector
				if selectorMap, ok := rawSelector.(map[string]interface{}); ok {
					if rawType, ok := selectorMap["type"]; ok {
						selector.Type = fmt.Sprintf("%s", rawType)
						// handle backward compatibility for "defsec" source type which is now "cloud"
						if selector.Type == string(iacTypes.SourceDefsec) {
							selector.Type = string(iacTypes.SourceCloud)
						}
					}
					if subType, ok := selectorMap["subtypes"].([]interface{}); ok {
						for _, subT := range subType {
							if st, ok := subT.(map[string]interface{}); ok {
								s := SubType{}
								_ = mapstructure.Decode(st, &s)
								selector.Subtypes = append(selector.Subtypes, s)
							}
						}
					}
				}
				options.Selectors = append(options.Selectors, selector)
			}
		}
	}

	return options

}

func getModuleNamespace(module *ast.Module) string {
	return strings.TrimPrefix(module.Package.Path.String(), "data.")
}
