package yaml

import (
	"bytes"
	"encoding"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"time"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/internal/errors"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"
	"golang.org/x/xerrors"
)

// Decoder reads and decodes YAML values from an input stream.
type Decoder struct {
	reader               io.Reader
	referenceReaders     []io.Reader
	anchorNodeMap        map[string]ast.Node
	anchorValueMap       map[string]reflect.Value
	opts                 []DecodeOption
	referenceFiles       []string
	referenceDirs        []string
	isRecursiveDir       bool
	isResolvedReference  bool
	validator            StructValidator
	disallowUnknownField bool
	disallowDuplicateKey bool
	useOrderedMap        bool
	parsedFile           *ast.File
	streamIndex          int
}

// NewDecoder returns a new decoder that reads from r.
func NewDecoder(r io.Reader, opts ...DecodeOption) *Decoder {
	return &Decoder{
		reader:               r,
		anchorNodeMap:        map[string]ast.Node{},
		anchorValueMap:       map[string]reflect.Value{},
		opts:                 opts,
		referenceReaders:     []io.Reader{},
		referenceFiles:       []string{},
		referenceDirs:        []string{},
		isRecursiveDir:       false,
		isResolvedReference:  false,
		disallowUnknownField: false,
		disallowDuplicateKey: false,
		useOrderedMap:        false,
	}
}

func (d *Decoder) castToFloat(v interface{}) interface{} {
	switch vv := v.(type) {
	case int:
		return float64(vv)
	case int8:
		return float64(vv)
	case int16:
		return float64(vv)
	case int32:
		return float64(vv)
	case int64:
		return float64(vv)
	case uint:
		return float64(vv)
	case uint8:
		return float64(vv)
	case uint16:
		return float64(vv)
	case uint32:
		return float64(vv)
	case uint64:
		return float64(vv)
	case float32:
		return float64(vv)
	case float64:
		return vv
	case string:
		// if error occurred, return zero value
		f, _ := strconv.ParseFloat(vv, 64)
		return f
	}
	return 0
}

func (d *Decoder) mergeValueNode(value ast.Node) ast.Node {
	if value.Type() == ast.AliasType {
		aliasNode := value.(*ast.AliasNode)
		aliasName := aliasNode.Value.GetToken().Value
		return d.anchorNodeMap[aliasName]
	}
	return value
}

func (d *Decoder) mapKeyNodeToString(node ast.Node) string {
	key := d.nodeToValue(node)
	if key == nil {
		return "null"
	}
	if k, ok := key.(string); ok {
		return k
	}
	return fmt.Sprint(key)
}

func (d *Decoder) setToMapValue(node ast.Node, m map[string]interface{}) {
	switch n := node.(type) {
	case *ast.MappingValueNode:
		if n.Key.Type() == ast.MergeKeyType {
			d.setToMapValue(d.mergeValueNode(n.Value), m)
		} else {
			key := d.mapKeyNodeToString(n.Key)
			m[key] = d.nodeToValue(n.Value)
		}
	case *ast.MappingNode:
		for _, value := range n.Values {
			d.setToMapValue(value, m)
		}
	}
}

func (d *Decoder) setToOrderedMapValue(node ast.Node, m *MapSlice) {
	switch n := node.(type) {
	case *ast.MappingValueNode:
		if n.Key.Type() == ast.MergeKeyType {
			d.setToOrderedMapValue(d.mergeValueNode(n.Value), m)
		} else {
			key := d.mapKeyNodeToString(n.Key)
			*m = append(*m, MapItem{Key: key, Value: d.nodeToValue(n.Value)})
		}
	case *ast.MappingNode:
		for _, value := range n.Values {
			d.setToOrderedMapValue(value, m)
		}
	}
}

func (d *Decoder) nodeToValue(node ast.Node) interface{} {
	switch n := node.(type) {
	case *ast.NullNode:
		return nil
	case *ast.StringNode:
		return n.GetValue()
	case *ast.IntegerNode:
		return n.GetValue()
	case *ast.FloatNode:
		return n.GetValue()
	case *ast.BoolNode:
		return n.GetValue()
	case *ast.InfinityNode:
		return n.GetValue()
	case *ast.NanNode:
		return n.GetValue()
	case *ast.TagNode:
		switch token.ReservedTagKeyword(n.Start.Value) {
		case token.TimestampTag:
			t, _ := d.castToTime(n.Value)
			return t
		case token.IntegerTag:
			i, _ := strconv.Atoi(fmt.Sprint(d.nodeToValue(n.Value)))
			return i
		case token.FloatTag:
			return d.castToFloat(d.nodeToValue(n.Value))
		case token.NullTag:
			return nil
		case token.BinaryTag:
			b, _ := base64.StdEncoding.DecodeString(d.nodeToValue(n.Value).(string))
			return b
		case token.StringTag:
			return d.nodeToValue(n.Value)
		case token.MappingTag:
			return d.nodeToValue(n.Value)
		}
	case *ast.AnchorNode:
		anchorName := n.Name.GetToken().Value
		anchorValue := d.nodeToValue(n.Value)
		d.anchorNodeMap[anchorName] = n.Value
		return anchorValue
	case *ast.AliasNode:
		aliasName := n.Value.GetToken().Value
		node := d.anchorNodeMap[aliasName]
		return d.nodeToValue(node)
	case *ast.LiteralNode:
		return n.Value.GetValue()
	case *ast.MappingKeyNode:
		return d.nodeToValue(n.Value)
	case *ast.MappingValueNode:
		if n.Key.Type() == ast.MergeKeyType {
			value := d.mergeValueNode(n.Value)
			if d.useOrderedMap {
				m := MapSlice{}
				d.setToOrderedMapValue(value, &m)
				return m
			}
			m := map[string]interface{}{}
			d.setToMapValue(value, m)
			return m
		}
		key := d.mapKeyNodeToString(n.Key)
		if d.useOrderedMap {
			return MapSlice{{Key: key, Value: d.nodeToValue(n.Value)}}
		}
		return map[string]interface{}{
			key: d.nodeToValue(n.Value),
		}
	case *ast.MappingNode:
		if d.useOrderedMap {
			m := make(MapSlice, 0, len(n.Values))
			for _, value := range n.Values {
				d.setToOrderedMapValue(value, &m)
			}
			return m
		}
		m := make(map[string]interface{}, len(n.Values))
		for _, value := range n.Values {
			d.setToMapValue(value, m)
		}
		return m
	case *ast.SequenceNode:
		v := make([]interface{}, 0, len(n.Values))
		for _, value := range n.Values {
			v = append(v, d.nodeToValue(value))
		}
		return v
	}
	return nil
}

func (d *Decoder) resolveAlias(node ast.Node) ast.Node {
	switch n := node.(type) {
	case *ast.MappingNode:
		for idx, value := range n.Values {
			n.Values[idx] = d.resolveAlias(value).(*ast.MappingValueNode)
		}
	case *ast.TagNode:
		n.Value = d.resolveAlias(n.Value)
	case *ast.MappingKeyNode:
		n.Value = d.resolveAlias(n.Value)
	case *ast.MappingValueNode:
		if n.Key.Type() == ast.MergeKeyType && n.Value.Type() == ast.AliasType {
			value := d.resolveAlias(n.Value)
			keyColumn := n.Key.GetToken().Position.Column
			requiredColumn := keyColumn + 2
			value.AddColumn(requiredColumn)
			n.Value = value
		} else {
			n.Key = d.resolveAlias(n.Key)
			n.Value = d.resolveAlias(n.Value)
		}
	case *ast.SequenceNode:
		for idx, value := range n.Values {
			n.Values[idx] = d.resolveAlias(value)
		}
	case *ast.AliasNode:
		aliasName := n.Value.GetToken().Value
		return d.resolveAlias(d.anchorNodeMap[aliasName])
	}
	return node
}

func (d *Decoder) getMapNode(node ast.Node) (ast.MapNode, error) {
	if _, ok := node.(*ast.NullNode); ok {
		return nil, nil
	}
	if anchor, ok := node.(*ast.AnchorNode); ok {
		mapNode, ok := anchor.Value.(ast.MapNode)
		if ok {
			return mapNode, nil
		}
		return nil, xerrors.Errorf("%s node doesn't MapNode", anchor.Value.Type())
	}
	if alias, ok := node.(*ast.AliasNode); ok {
		aliasName := alias.Value.GetToken().Value
		node := d.anchorNodeMap[aliasName]
		if node == nil {
			return nil, xerrors.Errorf("cannot find anchor by alias name %s", aliasName)
		}
		mapNode, ok := node.(ast.MapNode)
		if ok {
			return mapNode, nil
		}
		return nil, xerrors.Errorf("%s node doesn't MapNode", node.Type())
	}
	mapNode, ok := node.(ast.MapNode)
	if !ok {
		return nil, xerrors.Errorf("%s node doesn't MapNode", node.Type())
	}
	return mapNode, nil
}

func (d *Decoder) getArrayNode(node ast.Node) (ast.ArrayNode, error) {
	if _, ok := node.(*ast.NullNode); ok {
		return nil, nil
	}
	if anchor, ok := node.(*ast.AnchorNode); ok {
		arrayNode, ok := anchor.Value.(ast.ArrayNode)
		if ok {
			return arrayNode, nil
		}
		return nil, xerrors.Errorf("%s node doesn't ArrayNode", anchor.Value.Type())
	}
	if alias, ok := node.(*ast.AliasNode); ok {
		aliasName := alias.Value.GetToken().Value
		node := d.anchorNodeMap[aliasName]
		if node == nil {
			return nil, xerrors.Errorf("cannot find anchor by alias name %s", aliasName)
		}
		arrayNode, ok := node.(ast.ArrayNode)
		if ok {
			return arrayNode, nil
		}
		return nil, xerrors.Errorf("%s node doesn't ArrayNode", node.Type())
	}
	arrayNode, ok := node.(ast.ArrayNode)
	if !ok {
		return nil, xerrors.Errorf("%s node doesn't ArrayNode", node.Type())
	}
	return arrayNode, nil
}

func (d *Decoder) fileToNode(f *ast.File) ast.Node {
	for _, doc := range f.Docs {
		if v := d.nodeToValue(doc.Body); v != nil {
			return doc.Body
		}
	}
	return nil
}

func (d *Decoder) convertValue(v reflect.Value, typ reflect.Type) (reflect.Value, error) {
	if typ.Kind() != reflect.String {
		if !v.Type().ConvertibleTo(typ) {
			return reflect.Zero(typ), errTypeMismatch(typ, v.Type())
		}
		return v.Convert(typ), nil
	}
	// cast value to string
	switch v.Type().Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return reflect.ValueOf(fmt.Sprint(v.Int())), nil
	case reflect.Float32, reflect.Float64:
		return reflect.ValueOf(fmt.Sprint(v.Float())), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return reflect.ValueOf(fmt.Sprint(v.Uint())), nil
	case reflect.Bool:
		return reflect.ValueOf(fmt.Sprint(v.Bool())), nil
	}
	if !v.Type().ConvertibleTo(typ) {
		return reflect.Zero(typ), errTypeMismatch(typ, v.Type())
	}
	return v.Convert(typ), nil
}

type overflowError struct {
	dstType reflect.Type
	srcNum  string
}

func (e *overflowError) Error() string {
	return fmt.Sprintf("cannot unmarshal %s into Go value of type %s ( overflow )", e.srcNum, e.dstType)
}

func errOverflow(dstType reflect.Type, num string) *overflowError {
	return &overflowError{dstType: dstType, srcNum: num}
}

type typeError struct {
	dstType         reflect.Type
	srcType         reflect.Type
	structFieldName *string
}

func (e *typeError) Error() string {
	if e.structFieldName != nil {
		return fmt.Sprintf("cannot unmarshal %s into Go struct field %s of type %s", e.srcType, *e.structFieldName, e.dstType)
	}
	return fmt.Sprintf("cannot unmarshal %s into Go value of type %s", e.srcType, e.dstType)
}

func errTypeMismatch(dstType, srcType reflect.Type) *typeError {
	return &typeError{dstType: dstType, srcType: srcType}
}

type unknownFieldError struct {
	err error
}

func (e *unknownFieldError) Error() string {
	return e.err.Error()
}

func errUnknownField(msg string, tk *token.Token) *unknownFieldError {
	return &unknownFieldError{err: errors.ErrSyntax(msg, tk)}
}

type duplicateKeyError struct {
	err error
}

func (e *duplicateKeyError) Error() string {
	return e.err.Error()
}

func errDuplicateKey(msg string, tk *token.Token) *duplicateKeyError {
	return &duplicateKeyError{err: errors.ErrSyntax(msg, tk)}
}

func (d *Decoder) deleteStructKeys(structType reflect.Type, unknownFields map[string]ast.Node) error {
	if structType.Kind() == reflect.Ptr {
		structType = structType.Elem()
	}
	structFieldMap, err := structFieldMap(structType)
	if err != nil {
		return errors.Wrapf(err, "failed to create struct field map")
	}

	for j := 0; j < structType.NumField(); j++ {
		field := structType.Field(j)
		if isIgnoredStructField(field) {
			continue
		}

		structField, exists := structFieldMap[field.Name]
		if !exists {
			continue
		}

		if structField.IsInline {
			d.deleteStructKeys(field.Type, unknownFields)
		} else {
			delete(unknownFields, structField.RenderName)
		}
	}
	return nil
}

func (d *Decoder) lastNode(node ast.Node) ast.Node {
	switch n := node.(type) {
	case *ast.MappingNode:
		if len(n.Values) > 0 {
			return d.lastNode(n.Values[len(n.Values)-1])
		}
	case *ast.MappingValueNode:
		return d.lastNode(n.Value)
	case *ast.SequenceNode:
		if len(n.Values) > 0 {
			return d.lastNode(n.Values[len(n.Values)-1])
		}
	}
	return node
}

func (d *Decoder) unmarshalableDocument(node ast.Node) []byte {
	node = d.resolveAlias(node)
	doc := node.String()
	last := d.lastNode(node)
	if last != nil && last.Type() == ast.LiteralType {
		doc += "\n"
	}
	return []byte(doc)
}

func (d *Decoder) unmarshalableText(node ast.Node) ([]byte, bool) {
	node = d.resolveAlias(node)
	if node.Type() == ast.AnchorType {
		node = node.(*ast.AnchorNode).Value
	}
	switch n := node.(type) {
	case *ast.StringNode:
		return []byte(n.Value), true
	case *ast.LiteralNode:
		return []byte(n.Value.GetToken().Value), true
	default:
		scalar, ok := n.(ast.ScalarNode)
		if ok {
			return []byte(fmt.Sprint(scalar.GetValue())), true
		}
	}
	return nil, false
}

func (d *Decoder) decodeValue(dst reflect.Value, src ast.Node) error {
	if src.Type() == ast.AnchorType {
		anchorName := src.(*ast.AnchorNode).Name.GetToken().Value
		if _, exists := d.anchorValueMap[anchorName]; !exists {
			d.anchorValueMap[anchorName] = dst
		}
	}
	valueType := dst.Type()
	if unmarshaler, ok := dst.Addr().Interface().(BytesUnmarshaler); ok {
		if err := unmarshaler.UnmarshalYAML(d.unmarshalableDocument(src)); err != nil {
			return errors.Wrapf(err, "failed to UnmarshalYAML")
		}
		return nil
	} else if unmarshaler, ok := dst.Addr().Interface().(InterfaceUnmarshaler); ok {
		if err := unmarshaler.UnmarshalYAML(func(v interface{}) error {
			rv := reflect.ValueOf(v)
			if rv.Type().Kind() != reflect.Ptr {
				return errors.ErrDecodeRequiredPointerType
			}
			if err := d.decodeValue(rv.Elem(), src); err != nil {
				return errors.Wrapf(err, "failed to decode value")
			}
			return nil
		}); err != nil {
			return errors.Wrapf(err, "failed to UnmarshalYAML")
		}
		return nil
	} else if _, ok := dst.Addr().Interface().(*time.Time); ok {
		return d.decodeTime(dst, src)
	} else if unmarshaler, isText := dst.Addr().Interface().(encoding.TextUnmarshaler); isText {
		b, ok := d.unmarshalableText(src)
		if ok {
			if err := unmarshaler.UnmarshalText(b); err != nil {
				return errors.Wrapf(err, "failed to UnmarshalText")
			}
			return nil
		}
	}
	switch valueType.Kind() {
	case reflect.Ptr:
		if dst.IsNil() {
			return nil
		}
		if src.Type() == ast.NullType {
			// set nil value to pointer
			dst.Set(reflect.Zero(valueType))
			return nil
		}
		v := d.createDecodableValue(dst.Type())
		if err := d.decodeValue(v, src); err != nil {
			return errors.Wrapf(err, "failed to decode ptr value")
		}
		dst.Set(d.castToAssignableValue(v, dst.Type()))
	case reflect.Interface:
		v := reflect.ValueOf(d.nodeToValue(src))
		if v.IsValid() {
			dst.Set(v)
		}
	case reflect.Map:
		return d.decodeMap(dst, src)
	case reflect.Array:
		return d.decodeArray(dst, src)
	case reflect.Slice:
		if mapSlice, ok := dst.Addr().Interface().(*MapSlice); ok {
			return d.decodeMapSlice(mapSlice, src)
		}
		return d.decodeSlice(dst, src)
	case reflect.Struct:
		if mapItem, ok := dst.Addr().Interface().(*MapItem); ok {
			return d.decodeMapItem(mapItem, src)
		}
		return d.decodeStruct(dst, src)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v := d.nodeToValue(src)
		switch vv := v.(type) {
		case int64:
			if !dst.OverflowInt(vv) {
				dst.SetInt(vv)
				return nil
			}
		case uint64:
			if vv <= math.MaxInt64 && !dst.OverflowInt(int64(vv)) {
				dst.SetInt(int64(vv))
				return nil
			}
		case float64:
			if vv <= math.MaxInt64 && !dst.OverflowInt(int64(vv)) {
				dst.SetInt(int64(vv))
				return nil
			}
		default:
			return errTypeMismatch(valueType, reflect.TypeOf(v))
		}
		return errOverflow(valueType, fmt.Sprint(v))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v := d.nodeToValue(src)
		switch vv := v.(type) {
		case int64:
			if 0 <= vv && !dst.OverflowUint(uint64(vv)) {
				dst.SetUint(uint64(vv))
				return nil
			}
		case uint64:
			if !dst.OverflowUint(vv) {
				dst.SetUint(vv)
				return nil
			}
		case float64:
			if 0 <= vv && vv <= math.MaxUint64 && !dst.OverflowUint(uint64(vv)) {
				dst.SetUint(uint64(vv))
				return nil
			}
		default:
			return errTypeMismatch(valueType, reflect.TypeOf(v))
		}
		return errOverflow(valueType, fmt.Sprint(v))
	}
	v := reflect.ValueOf(d.nodeToValue(src))
	if v.IsValid() {
		convertedValue, err := d.convertValue(v, dst.Type())
		if err != nil {
			return errors.Wrapf(err, "failed to convert value")
		}
		dst.Set(convertedValue)
	}
	return nil
}

func (d *Decoder) createDecodableValue(typ reflect.Type) reflect.Value {
	for {
		if typ.Kind() == reflect.Ptr {
			typ = typ.Elem()
			continue
		}
		break
	}
	return reflect.New(typ).Elem()
}

func (d *Decoder) castToAssignableValue(value reflect.Value, target reflect.Type) reflect.Value {
	if target.Kind() != reflect.Ptr {
		return value
	}
	maxTryCount := 5
	tryCount := 0
	for {
		if tryCount > maxTryCount {
			return value
		}
		if value.Type().AssignableTo(target) {
			break
		}
		value = value.Addr()
		tryCount++
	}
	return value
}

func (d *Decoder) createDecodedNewValue(typ reflect.Type, node ast.Node) (reflect.Value, error) {
	if node.Type() == ast.AliasType {
		aliasName := node.(*ast.AliasNode).Value.GetToken().Value
		newValue := d.anchorValueMap[aliasName]
		if newValue.IsValid() {
			return newValue, nil
		}
	}
	if node.Type() == ast.NullType {
		return reflect.Zero(typ), nil
	}
	newValue := d.createDecodableValue(typ)
	if err := d.decodeValue(newValue, node); err != nil {
		return newValue, errors.Wrapf(err, "failed to decode value")
	}
	return newValue, nil
}

func (d *Decoder) keyToNodeMap(node ast.Node, ignoreMergeKey bool, getKeyOrValueNode func(*ast.MapNodeIter) ast.Node) (map[string]ast.Node, error) {
	mapNode, err := d.getMapNode(node)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get map node")
	}
	keyMap := map[string]struct{}{}
	keyToNodeMap := map[string]ast.Node{}
	if mapNode == nil {
		return keyToNodeMap, nil
	}
	mapIter := mapNode.MapRange()
	for mapIter.Next() {
		keyNode := mapIter.Key()
		if keyNode.Type() == ast.MergeKeyType {
			if ignoreMergeKey {
				continue
			}
			mergeMap, err := d.keyToNodeMap(mapIter.Value(), ignoreMergeKey, getKeyOrValueNode)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to get keyToNodeMap by MergeKey node")
			}
			for k, v := range mergeMap {
				if err := d.validateDuplicateKey(keyMap, k, v); err != nil {
					return nil, errors.Wrapf(err, "invalid struct key")
				}
				keyToNodeMap[k] = v
			}
		} else {
			key, ok := d.nodeToValue(keyNode).(string)
			if !ok {
				return nil, errors.Wrapf(err, "failed to decode map key")
			}
			if err := d.validateDuplicateKey(keyMap, key, keyNode); err != nil {
				return nil, errors.Wrapf(err, "invalid struct key")
			}
			keyToNodeMap[key] = getKeyOrValueNode(mapIter)
		}
	}
	return keyToNodeMap, nil
}

func (d *Decoder) keyToKeyNodeMap(node ast.Node, ignoreMergeKey bool) (map[string]ast.Node, error) {
	m, err := d.keyToNodeMap(node, ignoreMergeKey, func(nodeMap *ast.MapNodeIter) ast.Node { return nodeMap.Key() })
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get keyToNodeMap")
	}
	return m, nil
}

func (d *Decoder) keyToValueNodeMap(node ast.Node, ignoreMergeKey bool) (map[string]ast.Node, error) {
	m, err := d.keyToNodeMap(node, ignoreMergeKey, func(nodeMap *ast.MapNodeIter) ast.Node { return nodeMap.Value() })
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get keyToNodeMap")
	}
	return m, nil
}

func (d *Decoder) setDefaultValueIfConflicted(v reflect.Value, fieldMap StructFieldMap) error {
	typ := v.Type()
	if typ.Kind() != reflect.Struct {
		return nil
	}
	embeddedStructFieldMap, err := structFieldMap(typ)
	if err != nil {
		return errors.Wrapf(err, "failed to get struct field map by embedded type")
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if isIgnoredStructField(field) {
			continue
		}
		structField := embeddedStructFieldMap[field.Name]
		if !fieldMap.isIncludedRenderName(structField.RenderName) {
			continue
		}
		// if declared same key name, set default value
		fieldValue := v.Field(i)
		if fieldValue.CanSet() {
			fieldValue.Set(reflect.Zero(fieldValue.Type()))
		}
	}
	return nil
}

// This is a subset of the formats allowed by the regular expression
// defined at http://yaml.org/type/timestamp.html.
var allowedTimestampFormats = []string{
	"2006-1-2T15:4:5.999999999Z07:00", // RCF3339Nano with short date fields.
	"2006-1-2t15:4:5.999999999Z07:00", // RFC3339Nano with short date fields and lower-case "t".
	"2006-1-2 15:4:5.999999999",       // space separated with no time zone
	"2006-1-2",                        // date only
}

func (d *Decoder) castToTime(src ast.Node) (time.Time, error) {
	if src == nil {
		return time.Time{}, nil
	}
	v := d.nodeToValue(src)
	if t, ok := v.(time.Time); ok {
		return t, nil
	}
	s, ok := v.(string)
	if !ok {
		return time.Time{}, errTypeMismatch(reflect.TypeOf(time.Time{}), reflect.TypeOf(v))
	}
	for _, format := range allowedTimestampFormats {
		t, err := time.Parse(format, s)
		if err != nil {
			// invalid format
			continue
		}
		return t, nil
	}
	return time.Time{}, nil
}

func (d *Decoder) decodeTime(dst reflect.Value, src ast.Node) error {
	t, err := d.castToTime(src)
	if err != nil {
		return err
	}
	dst.Set(reflect.ValueOf(t))
	return nil
}

// getMergeAliasName support single alias only
func (d *Decoder) getMergeAliasName(src ast.Node) string {
	mapNode, err := d.getMapNode(src)
	if err != nil {
		return ""
	}
	if mapNode == nil {
		return ""
	}
	mapIter := mapNode.MapRange()
	for mapIter.Next() {
		key := mapIter.Key()
		value := mapIter.Value()
		if key.Type() == ast.MergeKeyType && value.Type() == ast.AliasType {
			return value.(*ast.AliasNode).Value.GetToken().Value
		}
	}
	return ""
}

func (d *Decoder) decodeStruct(dst reflect.Value, src ast.Node) error {
	if src == nil {
		return nil
	}
	structType := dst.Type()
	structFieldMap, err := structFieldMap(structType)
	if err != nil {
		return errors.Wrapf(err, "failed to create struct field map")
	}
	ignoreMergeKey := structFieldMap.hasMergeProperty()
	keyToNodeMap, err := d.keyToValueNodeMap(src, ignoreMergeKey)
	if err != nil {
		return errors.Wrapf(err, "failed to get keyToValueNodeMap")
	}
	var unknownFields map[string]ast.Node
	if d.disallowUnknownField {
		unknownFields, err = d.keyToKeyNodeMap(src, ignoreMergeKey)
		if err != nil {
			return errors.Wrapf(err, "failed to get keyToKeyNodeMap")
		}
	}

	aliasName := d.getMergeAliasName(src)
	var foundErr error

	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		if isIgnoredStructField(field) {
			continue
		}
		structField := structFieldMap[field.Name]
		if structField.IsInline {
			fieldValue := dst.FieldByName(field.Name)
			if structField.IsAutoAlias {
				if aliasName != "" {
					newFieldValue := d.anchorValueMap[aliasName]
					if newFieldValue.IsValid() {
						fieldValue.Set(d.castToAssignableValue(newFieldValue, fieldValue.Type()))
					}
				}
				continue
			}
			if !fieldValue.CanSet() {
				return xerrors.Errorf("cannot set embedded type as unexported field %s.%s", field.PkgPath, field.Name)
			}
			if fieldValue.Type().Kind() == reflect.Ptr && src.Type() == ast.NullType {
				// set nil value to pointer
				fieldValue.Set(reflect.Zero(fieldValue.Type()))
				continue
			}
			mapNode := ast.Mapping(nil, false)
			for k, v := range keyToNodeMap {
				key := &ast.StringNode{BaseNode: &ast.BaseNode{}, Value: k}
				mapNode.Values = append(mapNode.Values, ast.MappingValue(nil, key, v))
			}
			newFieldValue, err := d.createDecodedNewValue(fieldValue.Type(), mapNode)
			if d.disallowUnknownField {
				var ufe *unknownFieldError
				if xerrors.As(err, &ufe) {
					err = nil
				}

				if err = d.deleteStructKeys(fieldValue.Type(), unknownFields); err != nil {
					return errors.Wrapf(err, "cannot delete struct keys")
				}
			}

			if err != nil {
				if foundErr != nil {
					continue
				}
				var te *typeError
				if xerrors.As(err, &te) {
					if te.structFieldName != nil {
						fieldName := fmt.Sprintf("%s.%s", structType.Name(), *te.structFieldName)
						te.structFieldName = &fieldName
					} else {
						fieldName := fmt.Sprintf("%s.%s", structType.Name(), field.Name)
						te.structFieldName = &fieldName
					}
					foundErr = te
					continue
				} else {
					foundErr = err
				}
				continue
			}
			d.setDefaultValueIfConflicted(newFieldValue, structFieldMap)
			fieldValue.Set(d.castToAssignableValue(newFieldValue, fieldValue.Type()))
			continue
		}
		v, exists := keyToNodeMap[structField.RenderName]
		if !exists {
			continue
		}
		delete(unknownFields, structField.RenderName)
		fieldValue := dst.FieldByName(field.Name)
		if fieldValue.Type().Kind() == reflect.Ptr && src.Type() == ast.NullType {
			// set nil value to pointer
			fieldValue.Set(reflect.Zero(fieldValue.Type()))
			continue
		}
		newFieldValue, err := d.createDecodedNewValue(fieldValue.Type(), v)
		if err != nil {
			if foundErr != nil {
				continue
			}
			var te *typeError
			if xerrors.As(err, &te) {
				fieldName := fmt.Sprintf("%s.%s", structType.Name(), field.Name)
				te.structFieldName = &fieldName
				foundErr = te
			} else {
				foundErr = err
			}
			continue
		}
		fieldValue.Set(d.castToAssignableValue(newFieldValue, fieldValue.Type()))
	}
	if foundErr != nil {
		return errors.Wrapf(foundErr, "failed to decode value")
	}

	if len(unknownFields) != 0 && d.disallowUnknownField {
		for key, node := range unknownFields {
			return errUnknownField(fmt.Sprintf(`unknown field "%s"`, key), node.GetToken())
		}
	}

	if d.validator != nil {
		if err := d.validator.Struct(dst.Interface()); err != nil {
			ev := reflect.ValueOf(err)
			if ev.Type().Kind() == reflect.Slice {
				for i := 0; i < ev.Len(); i++ {
					fieldErr, ok := ev.Index(i).Interface().(FieldError)
					if !ok {
						continue
					}
					fieldName := fieldErr.StructField()
					structField, exists := structFieldMap[fieldName]
					if !exists {
						continue
					}
					node, exists := keyToNodeMap[structField.RenderName]
					if exists {
						// TODO: to make FieldError message cutomizable
						return errors.ErrSyntax(fmt.Sprintf("%s", err), node.GetToken())
					}
				}
			}
		}
	}
	return nil
}

func (d *Decoder) decodeArray(dst reflect.Value, src ast.Node) error {
	arrayNode, err := d.getArrayNode(src)
	if err != nil {
		return errors.Wrapf(err, "failed to get array node")
	}
	if arrayNode == nil {
		return nil
	}
	iter := arrayNode.ArrayRange()
	arrayValue := reflect.New(dst.Type()).Elem()
	arrayType := dst.Type()
	elemType := arrayType.Elem()
	idx := 0

	var foundErr error
	for iter.Next() {
		v := iter.Value()
		if elemType.Kind() == reflect.Ptr && v.Type() == ast.NullType {
			// set nil value to pointer
			arrayValue.Index(idx).Set(reflect.Zero(elemType))
		} else {
			dstValue, err := d.createDecodedNewValue(elemType, v)
			if err != nil {
				if foundErr == nil {
					foundErr = err
				}
				continue
			} else {
				arrayValue.Index(idx).Set(d.castToAssignableValue(dstValue, elemType))
			}
		}
		idx++
	}
	dst.Set(arrayValue)
	if foundErr != nil {
		return errors.Wrapf(foundErr, "failed to decode value")
	}
	return nil
}

func (d *Decoder) decodeSlice(dst reflect.Value, src ast.Node) error {
	arrayNode, err := d.getArrayNode(src)
	if err != nil {
		return errors.Wrapf(err, "failed to get array node")
	}
	if arrayNode == nil {
		return nil
	}
	iter := arrayNode.ArrayRange()
	sliceType := dst.Type()
	sliceValue := reflect.MakeSlice(sliceType, 0, iter.Len())
	elemType := sliceType.Elem()

	var foundErr error
	for iter.Next() {
		v := iter.Value()
		if elemType.Kind() == reflect.Ptr && v.Type() == ast.NullType {
			// set nil value to pointer
			sliceValue = reflect.Append(sliceValue, reflect.Zero(elemType))
			continue
		}
		dstValue, err := d.createDecodedNewValue(elemType, v)
		if err != nil {
			if foundErr == nil {
				foundErr = err
			}
			continue
		}
		sliceValue = reflect.Append(sliceValue, d.castToAssignableValue(dstValue, elemType))
	}
	dst.Set(sliceValue)
	if foundErr != nil {
		return errors.Wrapf(foundErr, "failed to decode value")
	}
	return nil
}

func (d *Decoder) decodeMapItem(dst *MapItem, src ast.Node) error {
	mapNode, err := d.getMapNode(src)
	if err != nil {
		return errors.Wrapf(err, "failed to get map node")
	}
	if mapNode == nil {
		return nil
	}
	mapIter := mapNode.MapRange()
	if !mapIter.Next() {
		return nil
	}
	key := mapIter.Key()
	value := mapIter.Value()
	if key.Type() == ast.MergeKeyType {
		if err := d.decodeMapItem(dst, value); err != nil {
			return errors.Wrapf(err, "failed to decode map with merge key")
		}
		return nil
	}
	*dst = MapItem{
		Key:   d.nodeToValue(key),
		Value: d.nodeToValue(value),
	}
	return nil
}

func (d *Decoder) validateDuplicateKey(keyMap map[string]struct{}, key interface{}, keyNode ast.Node) error {
	k, ok := key.(string)
	if !ok {
		return nil
	}
	if d.disallowDuplicateKey {
		if _, exists := keyMap[k]; exists {
			return errDuplicateKey(fmt.Sprintf(`duplicate key "%s"`, k), keyNode.GetToken())
		}
	}
	keyMap[k] = struct{}{}
	return nil
}

func (d *Decoder) decodeMapSlice(dst *MapSlice, src ast.Node) error {
	mapNode, err := d.getMapNode(src)
	if err != nil {
		return errors.Wrapf(err, "failed to get map node")
	}
	if mapNode == nil {
		return nil
	}
	mapSlice := MapSlice{}
	mapIter := mapNode.MapRange()
	keyMap := map[string]struct{}{}
	for mapIter.Next() {
		key := mapIter.Key()
		value := mapIter.Value()
		if key.Type() == ast.MergeKeyType {
			var m MapSlice
			if err := d.decodeMapSlice(&m, value); err != nil {
				return errors.Wrapf(err, "failed to decode map with merge key")
			}
			for _, v := range m {
				if err := d.validateDuplicateKey(keyMap, v.Key, value); err != nil {
					return errors.Wrapf(err, "invalid map key")
				}
				mapSlice = append(mapSlice, v)
			}
			continue
		}
		k := d.nodeToValue(key)
		if err := d.validateDuplicateKey(keyMap, k, key); err != nil {
			return errors.Wrapf(err, "invalid map key")
		}
		mapSlice = append(mapSlice, MapItem{
			Key:   k,
			Value: d.nodeToValue(value),
		})
	}
	*dst = mapSlice
	return nil
}

func (d *Decoder) decodeMap(dst reflect.Value, src ast.Node) error {
	mapNode, err := d.getMapNode(src)
	if err != nil {
		return errors.Wrapf(err, "failed to get map node")
	}
	if mapNode == nil {
		return nil
	}
	mapType := dst.Type()
	mapValue := reflect.MakeMap(mapType)
	keyType := mapValue.Type().Key()
	valueType := mapValue.Type().Elem()
	mapIter := mapNode.MapRange()
	keyMap := map[string]struct{}{}
	var foundErr error
	for mapIter.Next() {
		key := mapIter.Key()
		value := mapIter.Value()
		if key.Type() == ast.MergeKeyType {
			if err := d.decodeMap(dst, value); err != nil {
				return errors.Wrapf(err, "failed to decode map with merge key")
			}
			iter := dst.MapRange()
			for iter.Next() {
				if err := d.validateDuplicateKey(keyMap, iter.Key(), value); err != nil {
					return errors.Wrapf(err, "invalid map key")
				}
				mapValue.SetMapIndex(iter.Key(), iter.Value())
			}
			continue
		}
		k := reflect.ValueOf(d.nodeToValue(key))
		if k.IsValid() && k.Type().ConvertibleTo(keyType) {
			k = k.Convert(keyType)
		}
		if k.IsValid() {
			if err := d.validateDuplicateKey(keyMap, k.Interface(), key); err != nil {
				return errors.Wrapf(err, "invalid map key")
			}
		}
		if valueType.Kind() == reflect.Ptr && value.Type() == ast.NullType {
			// set nil value to pointer
			mapValue.SetMapIndex(k, reflect.Zero(valueType))
			continue
		}
		dstValue, err := d.createDecodedNewValue(valueType, value)
		if err != nil {
			if foundErr == nil {
				foundErr = err
			}
		}
		if !k.IsValid() {
			// expect nil key
			mapValue.SetMapIndex(d.createDecodableValue(keyType), d.castToAssignableValue(dstValue, valueType))
			continue
		}
		mapValue.SetMapIndex(k, d.castToAssignableValue(dstValue, valueType))
	}
	dst.Set(mapValue)
	if foundErr != nil {
		return errors.Wrapf(foundErr, "failed to decode value")
	}
	return nil
}

func (d *Decoder) fileToReader(file string) (io.Reader, error) {
	reader, err := os.Open(file)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open file")
	}
	return reader, nil
}

func (d *Decoder) isYAMLFile(file string) bool {
	ext := filepath.Ext(file)
	if ext == ".yml" {
		return true
	}
	if ext == ".yaml" {
		return true
	}
	return false
}

func (d *Decoder) readersUnderDir(dir string) ([]io.Reader, error) {
	pattern := fmt.Sprintf("%s/*", dir)
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get files by %s", pattern)
	}
	readers := []io.Reader{}
	for _, match := range matches {
		if !d.isYAMLFile(match) {
			continue
		}
		reader, err := d.fileToReader(match)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get reader")
		}
		readers = append(readers, reader)
	}
	return readers, nil
}

func (d *Decoder) readersUnderDirRecursive(dir string) ([]io.Reader, error) {
	readers := []io.Reader{}
	if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if !d.isYAMLFile(path) {
			return nil
		}
		reader, err := d.fileToReader(path)
		if err != nil {
			return errors.Wrapf(err, "failed to get reader")
		}
		readers = append(readers, reader)
		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "interrupt walk in %s", dir)
	}
	return readers, nil
}

func (d *Decoder) resolveReference() error {
	for _, opt := range d.opts {
		if err := opt(d); err != nil {
			return errors.Wrapf(err, "failed to exec option")
		}
	}
	for _, file := range d.referenceFiles {
		reader, err := d.fileToReader(file)
		if err != nil {
			return errors.Wrapf(err, "failed to get reader")
		}
		d.referenceReaders = append(d.referenceReaders, reader)
	}
	for _, dir := range d.referenceDirs {
		if !d.isRecursiveDir {
			readers, err := d.readersUnderDir(dir)
			if err != nil {
				return errors.Wrapf(err, "failed to get readers from under the %s", dir)
			}
			d.referenceReaders = append(d.referenceReaders, readers...)
		} else {
			readers, err := d.readersUnderDirRecursive(dir)
			if err != nil {
				return errors.Wrapf(err, "failed to get readers from under the %s", dir)
			}
			d.referenceReaders = append(d.referenceReaders, readers...)
		}
	}
	for _, reader := range d.referenceReaders {
		bytes, err := ioutil.ReadAll(reader)
		if err != nil {
			return errors.Wrapf(err, "failed to read buffer")
		}

		// assign new anchor definition to anchorMap
		if _, err := d.parse(bytes); err != nil {
			return errors.Wrapf(err, "failed to decode")
		}
	}
	d.isResolvedReference = true
	return nil
}

func (d *Decoder) parse(bytes []byte) (*ast.File, error) {
	f, err := parser.ParseBytes(bytes, 0)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse yaml")
	}
	normalizedFile := &ast.File{}
	for _, doc := range f.Docs {
		// try to decode ast.Node to value and map anchor value to anchorMap
		if v := d.nodeToValue(doc.Body); v != nil {
			normalizedFile.Docs = append(normalizedFile.Docs, doc)
		}
	}
	return normalizedFile, nil
}

func (d *Decoder) isInitialized() bool {
	return d.parsedFile != nil
}

func (d *Decoder) decodeInit() error {
	if !d.isResolvedReference {
		if err := d.resolveReference(); err != nil {
			return errors.Wrapf(err, "failed to resolve reference")
		}
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, d.reader); err != nil {
		return errors.Wrapf(err, "failed to copy from reader")
	}
	file, err := d.parse(buf.Bytes())
	if err != nil {
		return errors.Wrapf(err, "failed to decode")
	}
	d.parsedFile = file
	return nil
}

func (d *Decoder) decode(v reflect.Value) error {
	if len(d.parsedFile.Docs) <= d.streamIndex {
		return io.EOF
	}
	body := d.parsedFile.Docs[d.streamIndex].Body
	if body == nil {
		return nil
	}
	if err := d.decodeValue(v.Elem(), body); err != nil {
		return errors.Wrapf(err, "failed to decode value")
	}
	d.streamIndex++
	return nil
}

// Decode reads the next YAML-encoded value from its input
// and stores it in the value pointed to by v.
//
// See the documentation for Unmarshal for details about the
// conversion of YAML into a Go value.
func (d *Decoder) Decode(v interface{}) error {
	rv := reflect.ValueOf(v)
	if rv.Type().Kind() != reflect.Ptr {
		return errors.ErrDecodeRequiredPointerType
	}
	if d.isInitialized() {
		if err := d.decode(rv); err != nil {
			if err == io.EOF {
				return err
			}
			return errors.Wrapf(err, "failed to decode")
		}
		return nil
	}
	if err := d.decodeInit(); err != nil {
		return errors.Wrapf(err, "failed to decodInit")
	}
	if err := d.decode(rv); err != nil {
		if err == io.EOF {
			return err
		}
		return errors.Wrapf(err, "failed to decode")
	}
	return nil
}
