package cftypes

import "reflect"

type CfType string

const (
	String  CfType = "string"
	Int     CfType = "int"
	Float64 CfType = "float64"
	Bool    CfType = "bool"
	Map     CfType = "map"
	List    CfType = "list"
	Unknown CfType = "unknown"
)

func TypeFromGoValue(value any) CfType {
	if value == nil {
		return Unknown
	}
	switch reflect.TypeOf(value).Kind() {
	case reflect.String:
		return String
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return Int
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return Int
	case reflect.Float32, reflect.Float64:
		return Float64
	case reflect.Bool:
		return Bool
	case reflect.Map:
		return Map
	case reflect.Slice:
		return List
	default:
		return Unknown
	}
}
