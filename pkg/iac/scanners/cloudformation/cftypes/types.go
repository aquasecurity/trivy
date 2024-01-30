package cftypes

type CfType string

const (
	String  CfType = "string"
	Int     CfType = "int"
	Float64 CfType = "float64"
	Bool    CfType = "bool"
	Map     CfType = "map"
	List    CfType = "list"
)
