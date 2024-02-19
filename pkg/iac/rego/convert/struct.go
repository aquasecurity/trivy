package convert

import (
	"reflect"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/types"
)

type metadataProvider interface {
	GetMetadata() types.Metadata
}

var metadataInterface = reflect.TypeOf((*metadataProvider)(nil)).Elem()

func StructToRego(inputValue reflect.Value) map[string]interface{} {

	// make sure we have a struct literal
	for inputValue.Type().Kind() == reflect.Ptr || inputValue.Type().Kind() == reflect.Interface {
		if inputValue.IsNil() {
			return nil
		}
		inputValue = inputValue.Elem()
	}
	if inputValue.Type().Kind() != reflect.Struct {
		panic("not a struct")
	}

	output := make(map[string]interface{}, inputValue.NumField())

	for i := 0; i < inputValue.NumField(); i++ {
		field := inputValue.Field(i)
		typ := inputValue.Type().Field(i)
		name := typ.Name
		if !typ.IsExported() {
			continue
		}
		if field.Interface() == nil {
			continue
		}
		val := anonymousToRego(reflect.ValueOf(field.Interface()))
		if val == nil {
			continue
		}
		key := strings.ToLower(name)
		if _, ok := field.Interface().(types.Metadata); key == "metadata" && ok {
			continue
		}
		output[strings.ToLower(name)] = val
	}

	if inputValue.Type().Implements(metadataInterface) {
		returns := inputValue.MethodByName("GetMetadata").Call(nil)
		if metadata, ok := returns[0].Interface().(types.Metadata); ok {
			output["__defsec_metadata"] = metadata.ToRego()
		}
	} else {
		metaVal := inputValue.FieldByName("Metadata")
		if metaVal.Kind() == reflect.Struct {
			if meta, ok := metaVal.Interface().(types.Metadata); ok {
				output["__defsec_metadata"] = meta.ToRego()
			}
		}

	}

	return output
}
