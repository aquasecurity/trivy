package armjson

import (
	"errors"
	"fmt"
	"reflect"
)

func (n *node) decodeNumber(v reflect.Value) error {

	switch v.Kind() {
	case reflect.Int64, reflect.Int32, reflect.Int16, reflect.Int8, reflect.Int:
		if i64, ok := n.raw.(int64); ok {
			v.SetInt(i64)
			return nil
		}
		if f64, ok := n.raw.(float64); ok {
			v.SetInt(int64(f64))
			return nil
		}
	case reflect.Uint64, reflect.Uint32, reflect.Uint16, reflect.Uint8, reflect.Uint:
		if i64, ok := n.raw.(int64); ok {
			v.SetUint(uint64(i64))
			return nil
		}
		if f64, ok := n.raw.(float64); ok {
			v.SetUint(uint64(f64))
			return nil
		}
	case reflect.Float32, reflect.Float64:
		if i64, ok := n.raw.(int64); ok {
			v.SetFloat(float64(i64))
			return nil
		}
		if f64, ok := n.raw.(float64); ok {
			v.SetFloat(f64)
			return nil
		}
	case reflect.Interface:
		v.Set(reflect.ValueOf(n.raw))
		return nil
	default:
		return fmt.Errorf("cannot decode number value to %s target", v.Kind())
	}

	return errors.New("internal value is not numeric")
}
