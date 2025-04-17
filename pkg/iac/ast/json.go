package ast

import (
	"fmt"
	"reflect"
	"strconv"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

func (n *Node) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	var valPtr any
	var kind NodeKind
	switch k := dec.PeekKind(); k {
	case 't', 'f':
		valPtr = new(bool)
		kind = BoolNode
	case '"':
		kind = StringNode
		valPtr = new(string)
	case '0':
		return n.parseNumericValue(dec)
	case '[', 'n':
		valPtr = new([]*Node)
		kind = SequenceNode
	case '{':
		valPtr = new(map[string]*Node)
		kind = MappingNode
	case 0:
		return dec.SkipValue()
	default:
		return fmt.Errorf("unexpected token kind %q at %d", k.String(), dec.InputOffset())
	}

	if err := json.UnmarshalDecode(dec, valPtr); err != nil {
		return err
	}

	n.Value = reflect.ValueOf(valPtr).Elem().Interface()
	n.Kind = kind
	return nil
}

func (p *Node) parseNumericValue(dec *jsontext.Decoder) error {
	raw, err := dec.ReadValue()
	if err != nil {
		return err
	}
	strVal := string(raw)

	if v, err := strconv.ParseInt(strVal, 10, 64); err == nil {
		p.Value = int(v)
		p.Kind = IntNode
		return nil
	}
	if v, err := strconv.ParseFloat(strVal, 64); err == nil {
		p.Value = v
		p.Kind = FloatNode
		return nil
	}
	return fmt.Errorf("invalid numeric value: %q", strVal)
}
