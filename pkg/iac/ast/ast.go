package ast

import (
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

type NodeKind int

const (
	MappingNode NodeKind = iota
	SequenceNode
	BoolNode
	StringNode
	IntNode
	FloatNode
	NullNode
	// YAML specific nodes
	TimestampNode
	BinaryNode
)

func (k NodeKind) String() string {
	switch k {
	case MappingNode:
		return "map"
	case SequenceNode:
		return "seq"
	case BoolNode:
		return "bool"
	case StringNode:
		return "string"
	case IntNode:
		return "int"
	case FloatNode:
		return "float"
	case NullNode:
		return "null"
	case TimestampNode:
		return "timestamp"
	case BinaryNode:
		return "binary"
	default:
		return "unknown"
	}
}

type Node struct {
	xjson.Location
	Kind  NodeKind
	Value any
}
