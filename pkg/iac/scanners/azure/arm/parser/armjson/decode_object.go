package armjson

import (
	"fmt"
	"reflect"
	"strings"
)

func (n *node) decodeObject(v reflect.Value) error {
	switch v.Kind() {
	case reflect.Struct:
		return n.decodeObjectToStruct(v)
	case reflect.Map:
		return n.decodeObjectToMap(v)
	case reflect.Interface:
		target := reflect.New(reflect.TypeOf(make(map[string]interface{}, len(n.Content())))).Elem()
		if err := n.decodeObjectToMap(target); err != nil {
			return err
		}
		v.Set(target)
		return nil
	default:
		return fmt.Errorf("cannot set object value to target of type %s", v.Kind())
	}
}

func (n *node) decodeObjectToMap(v reflect.Value) error {
	properties, err := n.objectAsMap()
	if err != nil {
		return err
	}

	newMap := reflect.MakeMap(v.Type())
	valueType := v.Type().Elem()

	for key, value := range properties {
		target := reflect.New(valueType).Elem()
		addressable := target
		if target.Kind() == reflect.Ptr {
			target.Set(reflect.New(valueType.Elem()))
		} else {
			addressable = target.Addr()
		}
		if err := value.(*node).decodeToValue(addressable); err != nil {
			return err
		}
		newMap.SetMapIndex(reflect.ValueOf(key), target)
	}

	v.Set(newMap)
	return nil

}

func (n *node) objectAsMap() (map[string]Node, error) {
	if n.kind != KindObject {
		return nil, fmt.Errorf("not an object")
	}
	properties := make(map[string]Node)
	contents := n.content
	for i := 0; i < len(contents); i += 2 {
		key := contents[i]
		if key.Kind() != KindString {
			return nil, fmt.Errorf("invalid object key - please report this bug")
		}
		keyStr := key.(*node).raw.(string)

		if i+1 >= len(contents) {
			return nil, fmt.Errorf("missing object value - please report this bug")
		}
		properties[keyStr] = contents[i+1]
	}
	return properties, nil
}

func (n *node) decodeObjectToStruct(v reflect.Value) error {

	temp := reflect.New(v.Type()).Elem()
	v.Set(temp)

	properties, err := n.objectAsMap()
	if err != nil {
		return err
	}

	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		fv := t.Field(i)
		tags := strings.Split(fv.Tag.Get("json"), ",")
		var tagName string
		for _, tag := range tags {
			if tag != "omitempty" && tag != "-" {
				tagName = tag
			}
		}
		if tagName == "" {
			tagName = fv.Name
		}

		value, ok := properties[tagName]
		if !ok {
			// TODO: should we zero this value?
			continue
		}

		subject := v.Field(i)

		// if fields are nil pointers, initialize them with values of the correct type
		if subject.Kind() == reflect.Ptr {
			if subject.IsNil() {
				subject.Set(reflect.New(subject.Type().Elem()))
			}
		} else {
			subject = subject.Addr()
		}

		if err := value.(*node).decodeToValue(subject); err != nil {
			return err
		}
	}
	return nil
}
