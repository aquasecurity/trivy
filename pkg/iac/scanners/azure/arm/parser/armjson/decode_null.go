package armjson

import (
	"reflect"
)

func (n *node) decodeNull(v reflect.Value) error {
	v.Set(reflect.Zero(v.Type()))
	return nil
}
