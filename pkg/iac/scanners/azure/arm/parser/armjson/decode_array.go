package armjson

import (
	"fmt"
	"reflect"
)

func (n *node) decodeArray(v reflect.Value) error {

	length := len(n.content)

	var original reflect.Value

	switch v.Kind() {
	case reflect.Array:
		if v.Len() != length {
			return fmt.Errorf("invalid length")
		}
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), length, length))
	case reflect.Interface:
		original = v
		slice := reflect.ValueOf(make([]interface{}, length))
		v = reflect.New(slice.Type()).Elem()
		v.Set(slice)
	default:
		return fmt.Errorf("invalid target type")
	}

	elementType := v.Type().Elem()
	for i, nodeElement := range n.content {
		node := nodeElement.(*node)
		targetElement := reflect.New(elementType).Elem()
		addressable := targetElement
		if targetElement.Kind() == reflect.Ptr {
			targetElement.Set(reflect.New(elementType.Elem()))
		} else {
			addressable = targetElement.Addr()
		}
		if err := node.decodeToValue(addressable); err != nil {
			return err
		}
		v.Index(i).Set(targetElement)
	}

	if original.IsValid() {
		original.Set(v)
	}

	return nil
}
