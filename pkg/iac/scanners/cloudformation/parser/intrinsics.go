package parser

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

var intrinsicFuncs map[string]func(property *Property) (*Property, bool)

func init() {
	intrinsicFuncs = map[string]func(property *Property) (*Property, bool){
		"Ref":             ResolveReference,
		"Fn::Base64":      ResolveBase64,
		"Fn::Equals":      ResolveEquals,
		"Fn::Join":        ResolveJoin,
		"Fn::Split":       ResolveSplit,
		"Fn::Sub":         ResolveSub,
		"Fn::FindInMap":   ResolveFindInMap,
		"Fn::Select":      ResolveSelect,
		"Fn::GetAtt":      ResolveGetAtt,
		"Fn::GetAZs":      GetAzs,
		"Fn::Cidr":        GetCidr,
		"Fn::ImportValue": ImportPlaceholder,
		"Fn::If":          ResolveIf,
		"Fn::And":         ResolveAnd,
		"Fn::Or":          ResolveOr,
		"Fn::Not":         ResolveNot,
		"Fn::Length":      ResolveLength,
		"Condition":       ResolveCondition,
	}
}

func ImportPlaceholder(property *Property) (*Property, bool) {
	property.unresolved = true
	return property, false
}

func PassthroughResolution(property *Property) (*Property, bool) {
	return property, false
}

func IsIntrinsicFunc(node *yaml.Node) bool {
	if node == nil || node.Tag == "" {
		return false
	}

	nodeTag := strings.TrimPrefix(node.Tag, "!")
	if nodeTag != "Ref" && nodeTag != "Condition" {
		nodeTag = fmt.Sprintf("Fn::%s", nodeTag)
	}
	for tag := range intrinsicFuncs {

		if nodeTag == tag {
			return true
		}
	}
	return false
}

func IsIntrinsic(key string) bool {
	for tag := range intrinsicFuncs {
		if tag == key {
			return true
		}
	}
	return false
}

func ResolveIntrinsicFunc(property *Property) (*Property, bool) {
	if property == nil {
		return nil, false
	}
	if !property.IsMap() {
		return property, false
	}

	for funcName := range property.AsMap() {
		if fn := intrinsicFuncs[funcName]; fn != nil {
			prop, resolved := fn(property)
			if prop == nil || !resolved {
				return prop, false
			}

			prop.inferType()
			return prop, true
		}
	}
	return property, false
}

func getIntrinsicTag(tag string) string {
	tag = strings.TrimPrefix(tag, "!")
	switch tag {
	case "Ref", "Contains":
		return tag
	default:
		return fmt.Sprintf("Fn::%s", tag)
	}
}

func abortIntrinsic(property *Property, _ string, _ ...string) (*Property, bool) {
	//
	return property, false
}
