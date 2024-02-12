package armjson

import (
	"fmt"
	"reflect"
)

func (n *node) decodeString(v reflect.Value) error {

	switch v.Kind() {
	case reflect.String:
		v.SetString(n.raw.(string))
	case reflect.Interface:
		v.Set(reflect.ValueOf(n.raw))
	default:
		return fmt.Errorf("cannot decode string value to non-string target: %s", v.Kind())
	}
	return nil
}
