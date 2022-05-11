# jfather

[![build](https://github.com/liamg/jfather/actions/workflows/test.yml/badge.svg)](https://github.com/liamg/jfather/actions/workflows/test.yml)

Parse JSON with line numbers and more!

This is a JSON parsing module that provides additional information during the unmarshalling process, such as line numbers, columns etc.

You can use jfather to unmarshal JSON just like the `encoding/json` package, and add your own unmarshalling functionality to gather metadata by implementing the `jfather.Umarshaller` interface. This requires a single method with the signature `UnmarshalJSONWithMetadata(node jfather.Node) error`. A full example is below.

You should not use this package unless you need the line/column metadata, as unmarshalling is typically much slower than the `encoding/json` package:

```
BenchmarkUnmarshal_JFather-8       	   39483	     34222 ns/op
BenchmarkUnmarshal_Traditional-8   	  176756	      7244 ns/op
```

## Full Example

```golang
package main

import (
	"fmt"

	"github.com/liamg/jfather"
)

type ExampleParent struct {
	Child ExampleChild `json:"child"`
}

type ExampleChild struct {
	Name   string
	Line   int
	Column int
}

func (t *ExampleChild) UnmarshalJSONWithMetadata(node jfather.Node) error {
	t.Line = node.Range().Start.Line
	t.Column = node.Range().Start.Column
	return node.Decode(&t.Name)
}

func main() {
	input := []byte(`{
	"child": "secret"
}`)
	var parent ExampleParent
	if err := jfather.Unmarshal(input, &parent); err != nil {
		panic(err)
	}

	fmt.Printf("Child value is at line %d, column %d, and is set to '%s'\n",
		parent.Child.Line, parent.Child.Column, parent.Child.Name)

	// outputs:
	//  Child value is at line 2, column 12, and is set to 'secret'
}
```
