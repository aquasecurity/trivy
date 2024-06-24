package terraform

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"text/template"
)

type PlanReference struct {
	Value any
}

type PlanBlock struct {
	Type       string
	Name       string
	BlockType  string
	Blocks     map[string]map[string]any
	Attributes map[string]any
}

func NewPlanBlock(blockType, resourceType, resourceName string) *PlanBlock {
	if blockType == "managed" {
		blockType = "resource"
	}

	return &PlanBlock{
		Type:       resourceType,
		Name:       resourceName,
		BlockType:  blockType,
		Blocks:     make(map[string]map[string]any),
		Attributes: make(map[string]any),
	}
}

func (rb *PlanBlock) HasAttribute(attribute string) bool {
	for k := range rb.Attributes {
		if k == attribute {
			return true
		}
	}
	return false
}

func (rb *PlanBlock) ToHCL() string {

	resourceTmpl, err := template.New("resource").Funcs(template.FuncMap{
		"RenderValue":     renderTemplateValue,
		"RenderPrimitive": renderPrimitive,
	}).Parse(resourceTemplate)
	if err != nil {
		panic(err)
	}

	var res bytes.Buffer
	if err := resourceTmpl.Execute(&res, map[string]any{
		"BlockType":  rb.BlockType,
		"Type":       rb.Type,
		"Name":       rb.Name,
		"Attributes": rb.Attributes,
		"Blocks":     rb.Blocks,
	}); err != nil {
		return ""
	}
	return res.String()
}

var resourceTemplate = `{{ .BlockType }} "{{ .Type }}" "{{ .Name }}" {
	{{ range $name, $value := .Attributes }}{{ if $value }}{{ $name }} {{ RenderValue $value }}
	{{end}}{{ end }}{{  range $name, $block := .Blocks }}{{ $name }} {
	{{ range $name, $value := $block }}{{ if $value }}{{ $name }} {{ RenderValue $value }}
	{{end}}{{ end }}}
{{end}}}`

func renderTemplateValue(val any) string {
	switch t := val.(type) {
	case map[string]any:
		return fmt.Sprintf("= %s", renderMap(t))
	case []any:
		if isMapSlice(t) {
			return renderSlice(t)
		}
		return fmt.Sprintf("= %s", renderSlice(t))
	default:
		return fmt.Sprintf("= %s", renderPrimitive(val))
	}
}

func renderPrimitive(val any) string {
	switch t := val.(type) {
	case PlanReference:
		return fmt.Sprintf("%v", t.Value)
	case string:
		return parseStringPrimitive(t)
	case map[string]any:
		return renderMap(t)
	case []any:
		return renderSlice(t)
	default:
		return fmt.Sprintf("%#v", t)
	}

}

func parseStringPrimitive(input string) string {
	// we must escape templating
	// ref: https://developer.hashicorp.com/terraform/language/expressions/strings#escape-sequences-1
	r := regexp.MustCompile(`((\$|\%)\{.+\})`)
	ff := r.ReplaceAllStringFunc(input, func(s string) string {
		s = strings.Replace(s, "$", "$$", 1)
		s = strings.Replace(s, "%", "%%", 1)
		return s
	})
	if strings.Contains(ff, "\n") {
		return fmt.Sprintf(`<<EOF
		%s
		EOF
		`, ff)
	}
	return fmt.Sprintf("%q", ff)
}

func isMapSlice(vars []any) bool {
	if len(vars) == 0 {
		return false
	}
	val := vars[0]
	switch val.(type) {
	case map[string]any:
		return true
	default:
		return false
	}
}

func renderSlice(vals []any) string {
	if len(vals) == 0 {
		return "[]"
	}

	val := vals[0]

	switch t := val.(type) {
	// if vals[0] is a map[string]interface this is a block, so render it as a map
	case map[string]any:
		return renderMap(t)
	// otherwise its going to be just a list of primitives
	default:
		result := "[\n"
		for _, v := range vals {
			result = fmt.Sprintf("%s\t%v,\n", result, renderPrimitive(v))
		}
		result = fmt.Sprintf("%s]", result)
		return result
	}
}

func renderMap(val map[string]any) string {
	if len(val) == 0 {
		return "{}"
	}

	result := "{\n"
	for k, v := range val {
		if v == nil {
			continue
		}
		result = fmt.Sprintf("%s\t%s = %s\n", result, k, renderPrimitive(v))
	}
	result = fmt.Sprintf("%s}", result)
	return result
}
