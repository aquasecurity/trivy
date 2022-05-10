package yaml

import (
	"encoding"
	"fmt"
	"io"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/internal/errors"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/printer"
	"github.com/goccy/go-yaml/token"
	"golang.org/x/xerrors"
)

const (
	// DefaultIndentSpaces default number of space for indent
	DefaultIndentSpaces = 2
)

// Encoder writes YAML values to an output stream.
type Encoder struct {
	writer             io.Writer
	opts               []EncodeOption
	indent             int
	isFlowStyle        bool
	isJSONStyle        bool
	anchorCallback     func(*ast.AnchorNode, interface{}) error
	anchorPtrToNameMap map[uintptr]string

	line        int
	column      int
	offset      int
	indentNum   int
	indentLevel int
}

// NewEncoder returns a new encoder that writes to w.
// The Encoder should be closed after use to flush all data to w.
func NewEncoder(w io.Writer, opts ...EncodeOption) *Encoder {
	return &Encoder{
		writer:             w,
		opts:               opts,
		indent:             DefaultIndentSpaces,
		anchorPtrToNameMap: map[uintptr]string{},
		line:               1,
		column:             1,
		offset:             0,
	}
}

// Close closes the encoder by writing any remaining data.
// It does not write a stream terminating string "...".
func (e *Encoder) Close() error {
	return nil
}

// Encode writes the YAML encoding of v to the stream.
// If multiple items are encoded to the stream,
// the second and subsequent document will be preceded with a "---" document separator,
// but the first will not.
//
// See the documentation for Marshal for details about the conversion of Go values to YAML.
func (e *Encoder) Encode(v interface{}) error {
	node, err := e.EncodeToNode(v)
	if err != nil {
		return errors.Wrapf(err, "failed to encode to node")
	}
	var p printer.Printer
	e.writer.Write(p.PrintNode(node))
	return nil
}

// EncodeToNode convert v to ast.Node.
func (e *Encoder) EncodeToNode(v interface{}) (ast.Node, error) {
	for _, opt := range e.opts {
		if err := opt(e); err != nil {
			return nil, errors.Wrapf(err, "failed to run option for encoder")
		}
	}
	node, err := e.encodeValue(reflect.ValueOf(v), 1)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to encode value")
	}
	return node, nil
}

func (e *Encoder) encodeDocument(doc []byte) (ast.Node, error) {
	f, err := parser.ParseBytes(doc, 0)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse yaml")
	}
	for _, docNode := range f.Docs {
		if docNode.Body != nil {
			return docNode.Body, nil
		}
	}
	return nil, nil
}

func (e *Encoder) isInvalidValue(v reflect.Value) bool {
	if !v.IsValid() {
		return true
	}
	kind := v.Type().Kind()
	if kind == reflect.Ptr && v.IsNil() {
		return true
	}
	if kind == reflect.Interface && v.IsNil() {
		return true
	}
	return false
}

func (e *Encoder) encodeValue(v reflect.Value, column int) (ast.Node, error) {
	if e.isInvalidValue(v) {
		return e.encodeNil(), nil
	}
	if v.CanInterface() {
		if marshaler, ok := v.Interface().(BytesMarshaler); ok {
			doc, err := marshaler.MarshalYAML()
			if err != nil {
				return nil, errors.Wrapf(err, "failed to MarshalYAML")
			}
			node, err := e.encodeDocument(doc)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to encode document")
			}
			return node, nil
		} else if marshaler, ok := v.Interface().(InterfaceMarshaler); ok {
			marshalV, err := marshaler.MarshalYAML()
			if err != nil {
				return nil, errors.Wrapf(err, "failed to MarshalYAML")
			}
			return e.encodeValue(reflect.ValueOf(marshalV), column)
		} else if t, ok := v.Interface().(time.Time); ok {
			return e.encodeTime(t, column), nil
		} else if marshaler, ok := v.Interface().(encoding.TextMarshaler); ok {
			doc, err := marshaler.MarshalText()
			if err != nil {
				return nil, errors.Wrapf(err, "failed to MarshalText")
			}
			node, err := e.encodeDocument(doc)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to encode document")
			}
			return node, nil
		}
	}
	switch v.Type().Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return e.encodeInt(v.Int()), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return e.encodeUint(v.Uint()), nil
	case reflect.Float32, reflect.Float64:
		return e.encodeFloat(v.Float()), nil
	case reflect.Ptr:
		anchorName := e.anchorPtrToNameMap[v.Pointer()]
		if anchorName != "" {
			aliasName := anchorName
			alias := ast.Alias(token.New("*", "*", e.pos(column)))
			alias.Value = ast.String(token.New(aliasName, aliasName, e.pos(column)))
			return alias, nil
		}
		return e.encodeValue(v.Elem(), column)
	case reflect.Interface:
		return e.encodeValue(v.Elem(), column)
	case reflect.String:
		return e.encodeString(v.String(), column), nil
	case reflect.Bool:
		return e.encodeBool(v.Bool()), nil
	case reflect.Slice:
		if mapSlice, ok := v.Interface().(MapSlice); ok {
			return e.encodeMapSlice(mapSlice, column)
		}
		return e.encodeSlice(v)
	case reflect.Struct:
		if v.CanInterface() {
			if mapItem, ok := v.Interface().(MapItem); ok {
				return e.encodeMapItem(mapItem, column)
			}
			if t, ok := v.Interface().(time.Time); ok {
				return e.encodeTime(t, column), nil
			}
		}
		return e.encodeStruct(v, column)
	case reflect.Map:
		return e.encodeMap(v, column), nil
	default:
		return nil, xerrors.Errorf("unknown value type %s", v.Type().String())
	}
	return nil, nil
}

func (e *Encoder) pos(column int) *token.Position {
	return &token.Position{
		Line:        e.line,
		Column:      column,
		Offset:      e.offset,
		IndentNum:   e.indentNum,
		IndentLevel: e.indentLevel,
	}
}

func (e *Encoder) encodeNil() ast.Node {
	value := "null"
	return ast.Null(token.New(value, value, e.pos(e.column)))
}

func (e *Encoder) encodeInt(v int64) ast.Node {
	value := fmt.Sprint(v)
	return ast.Integer(token.New(value, value, e.pos(e.column)))
}

func (e *Encoder) encodeUint(v uint64) ast.Node {
	value := fmt.Sprint(v)
	return ast.Integer(token.New(value, value, e.pos(e.column)))
}

func (e *Encoder) encodeFloat(v float64) ast.Node {
	if v == math.Inf(0) {
		value := ".inf"
		return ast.Infinity(token.New(value, value, e.pos(e.column)))
	} else if v == math.Inf(-1) {
		value := "-.inf"
		return ast.Infinity(token.New(value, value, e.pos(e.column)))
	} else if math.IsNaN(v) {
		value := ".nan"
		return ast.Nan(token.New(value, value, e.pos(e.column)))
	}
	value := fmt.Sprintf("%f", v)
	fvalue := strings.Split(value, ".")
	if len(fvalue) > 1 {
		precision := fvalue[1]
		precisionNum := 1
		for i := len(precision) - 1; i >= 0; i-- {
			if precision[i] != '0' {
				precisionNum = i + 1
				break
			}
		}
		value = strconv.FormatFloat(v, 'f', precisionNum, 64)
	}
	return ast.Float(token.New(value, value, e.pos(e.column)))
}

func (e *Encoder) encodeString(v string, column int) ast.Node {
	if e.isJSONStyle || token.IsNeedQuoted(v) {
		v = strconv.Quote(v)
	}
	return ast.String(token.New(v, v, e.pos(column)))
}

func (e *Encoder) encodeBool(v bool) ast.Node {
	value := fmt.Sprint(v)
	return ast.Bool(token.New(value, value, e.pos(e.column)))
}

func (e *Encoder) encodeSlice(value reflect.Value) (ast.Node, error) {
	sequence := ast.Sequence(token.New("-", "-", e.pos(e.column)), e.isFlowStyle)
	for i := 0; i < value.Len(); i++ {
		node, err := e.encodeValue(value.Index(i), e.column)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to encode value for slice")
		}
		sequence.Values = append(sequence.Values, node)
	}
	return sequence, nil
}

func (e *Encoder) encodeMapItem(item MapItem, column int) (*ast.MappingValueNode, error) {
	k := reflect.ValueOf(item.Key)
	v := reflect.ValueOf(item.Value)
	value, err := e.encodeValue(v, column)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to encode MapItem")
	}
	if m, ok := value.(*ast.MappingNode); ok {
		m.AddColumn(e.indent)
	}
	return ast.MappingValue(
		token.New("", "", e.pos(column)),
		e.encodeString(k.Interface().(string), column),
		value,
	), nil
}

func (e *Encoder) encodeMapSlice(value MapSlice, column int) (ast.Node, error) {
	node := ast.Mapping(token.New("", "", e.pos(column)), e.isFlowStyle)
	for _, item := range value {
		value, err := e.encodeMapItem(item, column)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to encode MapItem for MapSlice")
		}
		node.Values = append(node.Values, value)
	}
	return node, nil
}

func (e *Encoder) encodeMap(value reflect.Value, column int) ast.Node {
	node := ast.Mapping(token.New("", "", e.pos(column)), e.isFlowStyle)
	keys := []string{}
	for _, k := range value.MapKeys() {
		keys = append(keys, k.Interface().(string))
	}
	sort.Strings(keys)
	for _, key := range keys {
		k := reflect.ValueOf(key)
		v := value.MapIndex(k)
		value, err := e.encodeValue(v, column)
		if err != nil {
			return nil
		}
		if m, ok := value.(*ast.MappingNode); ok {
			m.AddColumn(e.indent)
		}
		node.Values = append(node.Values, ast.MappingValue(
			nil,
			e.encodeString(k.Interface().(string), column),
			value,
		))
	}
	return node
}

// IsZeroer is used to check whether an object is zero to determine
// whether it should be omitted when marshaling with the omitempty flag.
// One notable implementation is time.Time.
type IsZeroer interface {
	IsZero() bool
}

func (e *Encoder) isZeroValue(v reflect.Value) bool {
	kind := v.Kind()
	if z, ok := v.Interface().(IsZeroer); ok {
		if (kind == reflect.Ptr || kind == reflect.Interface) && v.IsNil() {
			return true
		}
		return z.IsZero()
	}
	switch kind {
	case reflect.String:
		return len(v.String()) == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	case reflect.Slice:
		return v.Len() == 0
	case reflect.Map:
		return v.Len() == 0
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Struct:
		vt := v.Type()
		for i := v.NumField() - 1; i >= 0; i-- {
			if vt.Field(i).PkgPath != "" {
				continue // private field
			}
			if !e.isZeroValue(v.Field(i)) {
				return false
			}
		}
		return true
	}
	return false
}

func (e *Encoder) encodeTime(v time.Time, column int) ast.Node {
	value := v.Format(time.RFC3339Nano)
	if e.isJSONStyle {
		value = strconv.Quote(value)
	}
	return ast.String(token.New(value, value, e.pos(column)))
}

func (e *Encoder) encodeAnchor(anchorName string, value ast.Node, fieldValue reflect.Value, column int) (ast.Node, error) {
	anchorNode := ast.Anchor(token.New("&", "&", e.pos(column)))
	anchorNode.Name = ast.String(token.New(anchorName, anchorName, e.pos(column)))
	anchorNode.Value = value
	if e.anchorCallback != nil {
		if err := e.anchorCallback(anchorNode, fieldValue.Interface()); err != nil {
			return nil, errors.Wrapf(err, "failed to marshal anchor")
		}
		if snode, ok := anchorNode.Name.(*ast.StringNode); ok {
			anchorName = snode.Value
		}
	}
	if fieldValue.Kind() == reflect.Ptr {
		e.anchorPtrToNameMap[fieldValue.Pointer()] = anchorName
	}
	return anchorNode, nil
}

func (e *Encoder) encodeStruct(value reflect.Value, column int) (ast.Node, error) {
	node := ast.Mapping(token.New("", "", e.pos(column)), e.isFlowStyle)
	structType := value.Type()
	structFieldMap, err := structFieldMap(structType)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get struct field map")
	}
	hasInlineAnchorField := false
	var inlineAnchorValue reflect.Value
	for i := 0; i < value.NumField(); i++ {
		field := structType.Field(i)
		if isIgnoredStructField(field) {
			continue
		}
		fieldValue := value.FieldByName(field.Name)
		structField := structFieldMap[field.Name]
		if structField.IsOmitEmpty && e.isZeroValue(fieldValue) {
			// omit encoding
			continue
		}
		value, err := e.encodeValue(fieldValue, column)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to encode value")
		}
		if m, ok := value.(*ast.MappingNode); ok {
			if !e.isFlowStyle && structField.IsFlow {
				m.IsFlowStyle = true
			}
			value.AddColumn(e.indent)
		} else if s, ok := value.(*ast.SequenceNode); ok {
			if !e.isFlowStyle && structField.IsFlow {
				s.IsFlowStyle = true
			}
		}
		key := e.encodeString(structField.RenderName, column)
		switch {
		case structField.AnchorName != "":
			anchorNode, err := e.encodeAnchor(structField.AnchorName, value, fieldValue, column)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to encode anchor")
			}
			value = anchorNode
		case structField.IsAutoAlias:
			if fieldValue.Kind() != reflect.Ptr {
				return nil, xerrors.Errorf(
					"%s in struct is not pointer type. but required automatically alias detection",
					structField.FieldName,
				)
			}
			anchorName := e.anchorPtrToNameMap[fieldValue.Pointer()]
			if anchorName == "" {
				return nil, xerrors.Errorf(
					"cannot find anchor name from pointer address for automatically alias detection",
				)
			}
			aliasName := anchorName
			alias := ast.Alias(token.New("*", "*", e.pos(column)))
			alias.Value = ast.String(token.New(aliasName, aliasName, e.pos(column)))
			value = alias
			if structField.IsInline {
				// if both used alias and inline, output `<<: *alias`
				key = ast.MergeKey(token.New("<<", "<<", e.pos(column)))
			}
		case structField.AliasName != "":
			aliasName := structField.AliasName
			alias := ast.Alias(token.New("*", "*", e.pos(column)))
			alias.Value = ast.String(token.New(aliasName, aliasName, e.pos(column)))
			value = alias
			if structField.IsInline {
				// if both used alias and inline, output `<<: *alias`
				key = ast.MergeKey(token.New("<<", "<<", e.pos(column)))
			}
		case structField.IsInline:
			isAutoAnchor := structField.IsAutoAnchor
			if !hasInlineAnchorField {
				hasInlineAnchorField = isAutoAnchor
			}
			if isAutoAnchor {
				inlineAnchorValue = fieldValue
			}
			mapNode, ok := value.(ast.MapNode)
			if !ok {
				return nil, xerrors.Errorf("inline value is must be map or struct type")
			}
			mapIter := mapNode.MapRange()
			for mapIter.Next() {
				key := mapIter.Key()
				value := mapIter.Value()
				keyName := key.GetToken().Value
				if structFieldMap.isIncludedRenderName(keyName) {
					// if declared same key name, skip encoding this field
					continue
				}
				key.AddColumn(-e.indent)
				value.AddColumn(-e.indent)
				node.Values = append(node.Values, ast.MappingValue(nil, key, value))
			}
			continue
		case structField.IsAutoAnchor:
			anchorNode, err := e.encodeAnchor(structField.RenderName, value, fieldValue, column)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to encode anchor")
			}
			value = anchorNode
		}
		node.Values = append(node.Values, ast.MappingValue(nil, key, value))
	}
	if hasInlineAnchorField {
		node.AddColumn(e.indent)
		anchorName := "anchor"
		anchorNode := ast.Anchor(token.New("&", "&", e.pos(column)))
		anchorNode.Name = ast.String(token.New(anchorName, anchorName, e.pos(column)))
		anchorNode.Value = node
		if e.anchorCallback != nil {
			if err := e.anchorCallback(anchorNode, value.Addr().Interface()); err != nil {
				return nil, errors.Wrapf(err, "failed to marshal anchor")
			}
			if snode, ok := anchorNode.Name.(*ast.StringNode); ok {
				anchorName = snode.Value
			}
		}
		if inlineAnchorValue.Kind() == reflect.Ptr {
			e.anchorPtrToNameMap[inlineAnchorValue.Pointer()] = anchorName
		}
		return anchorNode, nil
	}
	return node, nil
}
