package armjson

import (
	"fmt"
	"reflect"
)

func (n *node) decodeBoolean(v reflect.Value) error {
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(n.raw.(bool))
	case reflect.Interface:
		v.Set(reflect.ValueOf(n.raw))
	default:
		return fmt.Errorf("cannot decode boolean value to %s target", v.Kind())
	}
	return nil
}
