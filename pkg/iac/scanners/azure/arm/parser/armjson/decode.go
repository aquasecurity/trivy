package armjson

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func (n *node) Decode(target any) error {
	v := reflect.ValueOf(target)
	return n.decodeToValue(v)
}

func (n *node) Metadata() types.Metadata {
	return *n.metadata
}

var unmarshaller = reflect.TypeOf((*Unmarshaller)(nil)).Elem()
var receiver = reflect.TypeOf((*MetadataReceiver)(nil)).Elem()

func (n *node) decodeToValue(v reflect.Value) error {

	if v.Type().Implements(receiver) {
		rec := v
		defer func() {
			rec.MethodByName("SetMetadata").Call([]reflect.Value{reflect.ValueOf(n.metadata)})
		}()
	}
	if v.Type().Implements(unmarshaller) {
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
		return errors.New("target is not settable")
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
	case KindComment:
		return n.decodeString(v)
	case KindUnknown:
		return errors.New("cannot decode unknown kind")
	default:
		return fmt.Errorf("decoding of kind 0x%x is not supported", n.kind)
	}
}
