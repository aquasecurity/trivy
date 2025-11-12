package terraform

import (
	"fmt"
	"sort"
	"strings"
)

type PlanReference struct {
	Value any
}

type PlanBlock struct {
	Type       string
	Name       string
	BlockType  string
	Blocks     []*PlanBlock
	Attributes map[string]any
}

func (pb *PlanBlock) GetOrCreateBlock(name string) *PlanBlock {
	for _, cb := range pb.Blocks {
		if cb.Name == name {
			return cb
		}
	}
	newChildBlock := &PlanBlock{
		Name:       name,
		Attributes: make(map[string]any),
	}
	pb.Blocks = append(pb.Blocks, newChildBlock)
	return newChildBlock
}

func (pb *PlanBlock) ToHCL() string {
	return pb.render("")
}

func (b *PlanBlock) render(indent string) string {
	var sb strings.Builder

	sb.WriteString(indent)
	if b.BlockType != "" && b.Type != "" && b.Name != "" {
		sb.WriteString(fmt.Sprintf("%s \"%s\" \"%s\" {\n", b.BlockType, b.Type, b.Name))
	} else {
		sb.WriteString(fmt.Sprintf("%s {\n", b.Name))
	}

	keys := make([]string, 0, len(b.Attributes))
	for k := range b.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		value := b.Attributes[key]
		if value == nil {
			continue
		}
		sb.WriteString(renderAttributeLine(key, value, indent+"  "))
	}

	for _, child := range b.Blocks {
		sb.WriteString(child.render(indent + "  "))
	}

	sb.WriteString(indent)
	sb.WriteString("}\n")

	return sb.String()
}

func renderAttributeLine(key string, val any, indent string) string {
	return fmt.Sprintf("%s%s = %s\n", indent, key, renderAttributeValue(val, indent))
}

func renderAttributeValue(val any, indent string) string {
	switch t := val.(type) {
	case map[string]any:
		return renderMap(t, indent)
	case []any:
		return renderSlice(t, indent)
	default:
		return renderPrimitive(val)
	}
}

func renderPrimitive(val any) string {
	switch t := val.(type) {
	case PlanReference:
		return fmt.Sprintf("%v", t.Value)
	case string:
		return parseStringPrimitive(t)
	default:
		return fmt.Sprintf("%#v", t)
	}
}

func renderSlice(vals []any, indent string) string {
	if len(vals) == 0 {
		return "[]"
	}

	var sb strings.Builder
	sb.WriteString("[\n")
	for _, v := range vals {
		sb.WriteString(indent)
		sb.WriteString("  ")
		sb.WriteString(renderPrimitive(v))
		sb.WriteString(",\n")
	}
	sb.WriteString(indent)
	sb.WriteString("]")
	return sb.String()
}

func renderMap(val map[string]any, indent string) string {
	if len(val) == 0 {
		return "{}"
	}

	keys := make([]string, 0, len(val))
	for k := range val {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString("{\n")
	for _, k := range keys {
		v := val[k]
		if v == nil {
			continue
		}
		sb.WriteString(renderAttributeLine(k, v, indent+"  "))
	}
	sb.WriteString(indent)
	sb.WriteString("}")
	return sb.String()
}

func parseStringPrimitive(input string) string {
	// we must escape templating
	// ref: https://developer.hashicorp.com/terraform/language/expressions/strings#escape-sequences-1
	input = escapeSpecialSequences(input)
	if strings.Contains(input, "\n") {
		return fmt.Sprintf(`<<EOF
		%s
		EOF
		`, input)
	}
	return fmt.Sprintf("%q", input)
}

func escapeSpecialSequences(input string) string {
	var sb strings.Builder
	sb.Grow(len(input))
	for i, r := range input {
		if r == '$' || r == '%' {
			sb.WriteRune(r)
			remain := input[i+1:]

			// it's not a special sequence
			if remain == "" || remain[0] != '{' {
				continue
			}

			// sequence is already escaped
			if i > 0 && rune(input[i-1]) == r {
				continue
			}

			sb.WriteRune(r)
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
