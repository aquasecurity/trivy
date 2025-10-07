package rego

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

const annotationScopePackage = "package"

type StaticMetadata struct {
	Deprecated          bool
	ID                  string
	AVDID               string
	Title               string
	ShortCode           string
	Aliases             []string
	Description         string
	Severity            string
	RecommendedActions  string
	PrimaryURL          string
	References          []string
	InputOptions        InputOptions
	Package             string
	Frameworks          map[framework.Framework][]string
	Provider            string
	Service             string
	Library             bool
	CloudFormation      *scan.EngineMetadata
	Terraform           *scan.EngineMetadata
	Examples            string
	MinimumTrivyVersion string
}

func NewStaticMetadata(pkgPath string, inputOpt InputOptions) *StaticMetadata {
	return &StaticMetadata{
		ID:           "N/A",
		Title:        "N/A",
		Severity:     "UNKNOWN",
		Description:  fmt.Sprintf("Rego module: %s", pkgPath),
		Package:      pkgPath,
		InputOptions: inputOpt,
		Frameworks: map[framework.Framework][]string{
			framework.Default: {},
		},
	}
}

func (sm *StaticMetadata) populate(meta map[string]any) error {
	if sm.Frameworks == nil {
		sm.Frameworks = make(map[framework.Framework][]string)
	}

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
	upd(&sm.Examples, "examples")
	upd(&sm.MinimumTrivyVersion, "minimum_trivy_version")

	if raw, ok := meta["deprecated"]; ok {
		if dep, ok := raw.(bool); ok {
			sm.Deprecated = dep
		}
	}

	if raw, ok := meta["minimum_trivy_version"]; ok {
		sm.MinimumTrivyVersion = raw.(string)
	}

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

	if err := sm.updateFrameworks(meta); err != nil {
		return fmt.Errorf("failed to update frameworks: %w", err)
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

func (sm *StaticMetadata) updateFrameworks(meta map[string]any) error {
	raw, ok := meta["frameworks"]
	if !ok {
		return nil
	}

	frameworks, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("frameworks metadata is not an object, got %T", raw)
	}

	if len(frameworks) > 0 {
		sm.Frameworks = make(map[framework.Framework][]string)
	}

	for fw, rawIDs := range frameworks {
		ids, ok := rawIDs.([]any)
		if !ok {
			return fmt.Errorf("framework ids is not an array, got %T", rawIDs)
		}
		fr := framework.Framework(fw)
		for _, id := range ids {
			if str, ok := id.(string); ok {
				sm.Frameworks[fr] = append(sm.Frameworks[fr], str)
			} else {
				sm.Frameworks[fr] = []string{}
			}
		}
	}
	return nil
}

func (sm *StaticMetadata) updateAliases(meta map[string]any) {
	if raw, ok := meta["aliases"]; ok {
		if aliases, ok := raw.([]any); ok {
			for _, a := range aliases {
				sm.Aliases = append(sm.Aliases, fmt.Sprintf("%s", a))
			}
		}
	}
}

func (sm *StaticMetadata) matchAnyFramework(frameworks []framework.Framework) bool {
	if len(frameworks) == 0 {
		frameworks = []framework.Framework{framework.Default}
	}

	return slices.ContainsFunc(frameworks, func(fw framework.Framework) bool {
		_, exists := sm.Frameworks[fw]
		return exists
	})
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
		if err := sm.populate(custom); err != nil {
			return err
		}
	}
	if len(annotations.RelatedResources) > 0 {
		sm.PrimaryURL = annotations.RelatedResources[0].Ref.String()
	}
	return nil
}

func NewEngineMetadata(schema string, meta map[string]any) (*scan.EngineMetadata, error) {
	var sMap map[string]any
	if raw, ok := meta[schema]; ok {
		sMap, ok = raw.(map[string]any)
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
	switch links := sMap["links"].(type) {
	case string:
		em.Links = []string{links}
	case []any:
		for _, v := range links {
			if str, ok := v.(string); ok {
				em.Links = append(em.Links, str)
			}
		}
	}
	if val, ok := sMap["remediation_markdown"].(string); ok {
		em.RemediationMarkdown = val
	}

	return &em, nil
}

type InputOptions struct {
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

func (sm *StaticMetadata) ToRule() scan.Rule {

	provider := "generic"
	if sm.Provider != "" {
		provider = sm.Provider
	} else if len(sm.InputOptions.Selectors) > 0 {
		provider = sm.InputOptions.Selectors[0].Type
	}

	return scan.Rule{
		Deprecated:          sm.Deprecated,
		ID:                  sm.ID,
		AVDID:               sm.AVDID,
		Aliases:             append(sm.Aliases, sm.ID),
		ShortCode:           sm.ShortCode,
		Summary:             sm.Title,
		Explanation:         sm.Description,
		Impact:              "",
		Resolution:          sm.RecommendedActions,
		Provider:            providers.Provider(provider),
		Service:             cmp.Or(sm.Service, "general"),
		Links:               sm.References,
		Severity:            severity.Severity(sm.Severity),
		RegoPackage:         sm.Package,
		Frameworks:          sm.Frameworks,
		CloudFormation:      sm.CloudFormation,
		Terraform:           sm.Terraform,
		Examples:            sm.Examples,
		MinimumTrivyVersion: sm.MinimumTrivyVersion,
	}
}

func MetadataFromAnnotations(module *ast.Module) (*StaticMetadata, error) {
	if annotations := findPackageAnnotations(module); annotations != nil {
		input, err := inputFromAnnotations(annotations)
		if err != nil {
			return nil, fmt.Errorf("retrieve input from annotations: %w", err)
		}
		metadata := NewStaticMetadata(module.Package.Path.String(), input)
		if err := metadata.FromAnnotations(annotations); err != nil {
			return nil, err
		}
		return metadata, nil
	}
	return nil, nil
}

func inputFromAnnotations(annotations *ast.Annotations) (InputOptions, error) {
	if annotations == nil || annotations.Custom == nil {
		return InputOptions{}, nil
	}
	input, ok := annotations.Custom["input"]
	if !ok {
		return InputOptions{}, nil
	}

	rawInput, ok := input.(map[string]any)
	if !ok {
		return InputOptions{}, fmt.Errorf("input is not an object, got %T", input)
	}
	return parseMetadataInput(rawInput)
}

type MetadataRetriever struct {
	compiler *ast.Compiler
}

func NewMetadataRetriever(compiler *ast.Compiler) *MetadataRetriever {
	return &MetadataRetriever{
		compiler: compiler,
	}
}

func (m *MetadataRetriever) RetrieveMetadata(ctx context.Context, module *ast.Module, contents ...any) (*StaticMetadata, error) {
	// read metadata from official rego annotations if possible
	if metadata, err := MetadataFromAnnotations(module); err != nil {
		return nil, fmt.Errorf("retrieve metadata from annotations: %w", err)
	} else if metadata != nil {
		return metadata, nil
	}

	input, err := m.inputFromRule(ctx, module)
	if err != nil {
		return nil, fmt.Errorf("retrieve input from rule: %w", err)
	}
	metadata := NewStaticMetadata(module.Package.Path.String(), input)

	// otherwise, try to read metadata from the rego module itself
	// - we used to do this before annotations were a thing
	options := []func(*rego.Rego){
		rego.Query(ruleQuery(module, "__rego_metadata__")),
		rego.Compiler(m.compiler),
		rego.Capabilities(nil),
	}
	// support dynamic metadata fields
	for _, in := range contents {
		options = append(options, rego.Input(in))
	}

	set, err := rego.New(options...).Eval(ctx)
	if err != nil {
		return nil, err
	}

	// no metadata supplied
	if set == nil {
		return metadata, nil
	}

	if len(set) != 1 {
		return nil, errors.New("failed to parse metadata: unexpected set length")
	}
	if len(set[0].Expressions) != 1 {
		return nil, errors.New("failed to parse metadata: unexpected expression length")
	}
	expression := set[0].Expressions[0]
	meta, ok := expression.Value.(map[string]any)
	if !ok {
		return nil, errors.New("failed to parse metadata: not an object")
	}

	if err := metadata.populate(meta); err != nil {
		return nil, err
	}

	return metadata, nil
}

func (m *MetadataRetriever) inputFromRule(ctx context.Context, module *ast.Module) (InputOptions, error) {
	instance := rego.New(
		rego.Query(ruleQuery(module, "__rego_input__")),
		rego.Compiler(m.compiler),
		rego.Capabilities(nil),
	)
	resultSet, err := instance.Eval(ctx)
	if err != nil {
		return InputOptions{}, fmt.Errorf("evaluate input: %w", err)
	}

	if len(resultSet) != 1 || len(resultSet[0].Expressions) != 1 {
		return InputOptions{}, nil
	}

	expression := resultSet[0].Expressions[0]
	metadata, ok := expression.Value.(map[string]any)
	if !ok {
		return InputOptions{}, fmt.Errorf("result is not an object, got %T", expression.Value)
	}
	return parseMetadataInput(metadata)
}

func parseMetadataInput(input map[string]any) (InputOptions, error) {
	raw, ok := input["selector"]
	if !ok {
		return InputOptions{}, nil
	}

	each, ok := raw.([]any)
	if !ok {
		return InputOptions{}, fmt.Errorf("selector is not an array, got %T", raw)
	}

	var selectors []Selector
	for _, rawSelector := range each {
		if selectorMap, ok := rawSelector.(map[string]any); ok {
			selector, err := parseSelectorItem(selectorMap)
			if err != nil {
				return InputOptions{}, fmt.Errorf("parse selector item %v: %w", selectorMap, err)
			}
			selectors = append(selectors, selector)
		}
	}
	return InputOptions{Selectors: selectors}, nil
}

func parseSelectorItem(raw map[string]any) (Selector, error) {
	var selector Selector
	if rawType, ok := raw["type"]; ok {
		selector.Type = fmt.Sprintf("%s", rawType)
		// handle backward compatibility for "defsec" source type which is now "cloud"
		if selector.Type == string(iacTypes.SourceDefsec) {
			selector.Type = string(iacTypes.SourceCloud)
		}
	}
	if subType, ok := raw["subtypes"].([]any); ok {
		for _, subT := range subType {
			if st, ok := subT.(map[string]any); ok {
				var s SubType
				if err := mapstructure.Decode(st, &s); err != nil {
					return Selector{}, fmt.Errorf("decode subtype: %w", err)
				}
				selector.Subtypes = append(selector.Subtypes, s)
			}
		}
	}
	return selector, nil
}

func ruleQuery(module *ast.Module, rule string) string {
	return module.Package.Path.String() + "." + rule
}

func findPackageAnnotations(module *ast.Module) *ast.Annotations {
	return lo.FindOrElse(module.Annotations, nil, func(a *ast.Annotations) bool {
		return a.Scope == annotationScopePackage
	})
}
