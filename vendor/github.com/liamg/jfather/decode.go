package jfather

import (
	"fmt"
	"reflect"
)

func (n *node) Decode(target interface{}) error {
	v := reflect.ValueOf(target)
	return n.decodeToValue(v)
}

var inter = reflect.TypeOf((*Unmarshaller)(nil)).Elem()

func (n *node) decodeToValue(v reflect.Value) error {

	if v.Type().Implements(inter) {
		returns := v.MethodByName("UnmarshalJSONWithMetadata").Call([]reflect.Value{reflect.ValueOf(n)})
		if err := returns[0].Interface(); err != nil {
			return err.(error)
		}
		return nil
	}

	for v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if !v.CanSet() {
		return fmt.Errorf("target is not settable")
	}

	switch n.kind {
	case KindObject:
		return n.decodeObject(v)
	case KindArray:
		return n.decodeArray(v)
	case KindString:
		return n.decodeString(v)
	case KindNumber:
		return n.decodeNumber(v)
	case KindBoolean:
		return n.decodeBoolean(v)
	case KindNull:
		return n.decodeNull(v)
	case KindUnknown:
		return fmt.Errorf("cannot decode unknown kind")
	default:
		return fmt.Errorf("decoding of kind 0x%x is not supported", n.kind)
	}
}
