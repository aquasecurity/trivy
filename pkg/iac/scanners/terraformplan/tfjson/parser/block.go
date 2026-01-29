package parser

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

type PlanReference struct {
	Value string
}

type PlanBlock struct {
	Type       string
	Name       string
	BlockType  string
	Blocks     []*PlanBlock
	Attributes map[string]any
}

func (pb *PlanBlock) GetOrCreateBlock(typ string) *PlanBlock {
	for _, cb := range pb.Blocks {
		if cb.BlockType == typ {
			return cb
		}
	}
	newChildBlock := &PlanBlock{
		BlockType:  typ,
		Attributes: make(map[string]any),
	}
	pb.Blocks = append(pb.Blocks, newChildBlock)
	return newChildBlock
}

func (pb *PlanBlock) toHCL(w io.Writer) {
	r := &hclRenderer{
		w:      w,
		indent: "",
	}
	r.renderBlock(pb)
}

type hclRenderer struct {
	w      io.Writer
	indent string
}

func (r *hclRenderer) write(s string) {
	fmt.Fprint(r.w, s)
}

func (r *hclRenderer) writeln(s string) {
	fmt.Fprintln(r.w, s)
}

func (r *hclRenderer) writef(format string, args ...any) {
	fmt.Fprintf(r.w, format, args...)
}

func (r *hclRenderer) incIndent() {
	r.indent += "  "
}

func (r *hclRenderer) decIndent() {
	if len(r.indent) >= 2 {
		r.indent = r.indent[:len(r.indent)-2]
	}
}

func (r *hclRenderer) renderBlock(b *PlanBlock) {
	r.write(r.indent)
	if b.BlockType != "" && b.Type != "" && b.Name != "" {
		// top-level block
		r.writef("%s \"%s\" \"%s\" {\n", b.BlockType, b.Type, b.Name)
	} else {
		// child block
		r.writef("%s {\n", b.BlockType)
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
		r.renderAttributeLine(key, value)
	}

	sort.Slice(b.Blocks, func(i, j int) bool {
		return b.Blocks[i].BlockType < b.Blocks[j].BlockType
	})

	r.incIndent()
	for _, child := range b.Blocks {
		r.renderBlock(child)
	}
	r.decIndent()
	r.writeln(r.indent + "}")
}

func (r *hclRenderer) renderAttributeLine(key string, val any) {
	r.write(fmt.Sprintf("%s%s = ", r.indent+"  ", key))
	r.renderAttributeValue(val)
	r.writeln("")
}

func (r *hclRenderer) renderAttributeValue(val any) {
	switch t := val.(type) {
	case map[string]any:
		r.renderMap(t)
	case []any:
		r.renderSlice(t)
	default:
		renderPrimitive(r.w, val)
	}
}

func renderPrimitive(w io.Writer, val any) {
	switch t := val.(type) {
	case PlanReference:
		fmt.Fprint(w, t.Value)
	case string:
		fmt.Fprint(w, parseStringPrimitive(t))
	default:
		fmt.Fprintf(w, "%#v", t)
	}
}

func (r *hclRenderer) renderSlice(vals []any) {
	if len(vals) == 0 {
		r.write("[]")
		return
	}

	r.writeln("[")

	r.incIndent()
	defer r.decIndent()

	for _, v := range vals {
		r.write(r.indent + "  ")
		renderPrimitive(r.w, v)
		r.writeln(",")
	}
	r.write(r.indent + "]")
}

func (r *hclRenderer) renderMap(val map[string]any) {
	if len(val) == 0 {
		r.write("{}")
		return
	}

	keys := make([]string, 0, len(val))
	for k := range val {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	r.writeln("{")
	r.incIndent()
	defer r.decIndent()

	for _, k := range keys {
		v := val[k]
		if v == nil {
			continue
		}

		r.renderAttributeLine(strconv.Quote(k), v)
	}
	r.write(r.indent + "}")
}

func parseStringPrimitive(input string) string {
	input = escapeSpecialSequences(input)
	if strings.Contains(input, "\n") {
		return fmt.Sprintf("<<EOF\n%s\nEOF", input)
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
