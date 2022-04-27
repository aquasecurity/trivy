// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package module

import (
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/internal/wasm/instruction"
	"github.com/open-policy-agent/opa/internal/wasm/types"
)

type (
	// Module represents a WASM module.
	Module struct {
		Version  uint32
		Start    StartSection
		Type     TypeSection
		Import   ImportSection
		Function FunctionSection
		Table    TableSection
		Memory   MemorySection
		Element  ElementSection
		Global   GlobalSection
		Export   ExportSection
		Code     RawCodeSection
		Data     DataSection
		Customs  []CustomSection
		Names    NameSection
	}

	// StartSection represents a WASM start section.
	StartSection struct {
		FuncIndex *uint32
	}

	// TypeSection represents a WASM type section.
	TypeSection struct {
		Functions []FunctionType
	}

	// ImportSection represents a WASM import section.
	ImportSection struct {
		Imports []Import
	}

	// FunctionSection represents a WASM function section.
	FunctionSection struct {
		TypeIndices []uint32
	}

	// TableSection represents a WASM table section.
	TableSection struct {
		Tables []Table
	}

	// MemorySection represents a Wasm memory section.
	MemorySection struct {
		Memories []Memory
	}

	// ElementSection represents a WASM element section.
	ElementSection struct {
		Segments []ElementSegment
	}

	// GlobalSection represents a WASM global section.
	GlobalSection struct {
		Globals []Global
	}

	// ExportSection represents a WASM export section.
	ExportSection struct {
		Exports []Export
	}

	// RawCodeSection represents a WASM code section. The code section is left as a
	// raw byte sequence.
	RawCodeSection struct {
		Segments []RawCodeSegment
	}

	// DataSection represents a WASM data section.
	DataSection struct {
		Segments []DataSegment
	}

	// CustomSection represents a WASM custom section.
	CustomSection struct {
		Name string
		Data []byte
	}

	// NameSection represents the WASM custom section "name".
	NameSection struct {
		Module    string
		Functions []NameMap
		Locals    []LocalNameMap
	}

	// NameMap maps function or local arg indices to their names.
	NameMap struct {
		Index uint32
		Name  string
	}

	// LocalNameMap maps function indices, and argument indices for the args
	// of the indexed function to their names.
	LocalNameMap struct {
		FuncIndex uint32
		NameMap
	}

	// FunctionType represents a WASM function type definition.
	FunctionType struct {
		Params  []types.ValueType
		Results []types.ValueType
	}

	// Import represents a WASM import statement.
	Import struct {
		Module     string
		Name       string
		Descriptor ImportDescriptor
	}

	// ImportDescriptor represents a WASM import descriptor.
	ImportDescriptor interface {
		fmt.Stringer
		Kind() ImportDescriptorType
	}

	// ImportDescriptorType defines allowed kinds of import descriptors.
	ImportDescriptorType int

	// FunctionImport represents a WASM function import statement.
	FunctionImport struct {
		Func uint32
	}

	// MemoryImport represents a WASM memory import statement.
	MemoryImport struct {
		Mem MemType
	}

	// MemType defines the attributes of a memory import.
	MemType struct {
		Lim Limit
	}

	// TableImport represents a WASM table import statement.
	TableImport struct {
		Type types.ElementType
		Lim  Limit
	}

	// ElementSegment represents a WASM element segment.
	ElementSegment struct {
		Index   uint32
		Offset  Expr
		Indices []uint32
	}

	// GlobalImport represents a WASM global variable import statement.
	GlobalImport struct {
		Type    types.ValueType
		Mutable bool
	}

	// Limit represents a WASM limit.
	Limit struct {
		Min uint32
		Max *uint32
	}

	// Table represents a WASM table statement.
	Table struct {
		Type types.ElementType
		Lim  Limit
	}

	// Memory represents a Wasm memory statement.
	Memory struct {
		Lim Limit
	}

	// Global represents a WASM global statement.
	Global struct {
		Type    types.ValueType
		Mutable bool
		Init    Expr
	}

	// Export represents a WASM export statement.
	Export struct {
		Name       string
		Descriptor ExportDescriptor
	}

	// ExportDescriptor represents a WASM export descriptor.
	ExportDescriptor struct {
		Type  ExportDescriptorType
		Index uint32
	}

	// ExportDescriptorType defines the allowed kinds of export descriptors.
	ExportDescriptorType int

	// RawCodeSegment represents a binary-encoded WASM code segment.
	RawCodeSegment struct {
		Code []byte
	}

	// DataSegment represents a WASM data segment.
	DataSegment struct {
		Index  uint32
		Offset Expr
		Init   []byte
	}

	// Expr represents a WASM expression.
	Expr struct {
		Instrs []instruction.Instruction
	}

	// CodeEntry represents a code segment entry.
	CodeEntry struct {
		Func Function
	}

	// Function represents a function in a code segment.
	Function struct {
		Locals []LocalDeclaration
		Expr   Expr
	}

	// LocalDeclaration represents a local variable declaration.
	LocalDeclaration struct {
		Count uint32
		Type  types.ValueType
	}
)

// Defines the allowed kinds of imports.
const (
	FunctionImportType ImportDescriptorType = iota
	TableImportType
	MemoryImportType
	GlobalImportType
)

func (x ImportDescriptorType) String() string {
	switch x {
	case FunctionImportType:
		return "func"
	case TableImportType:
		return "table"
	case MemoryImportType:
		return "memory"
	case GlobalImportType:
		return "global"
	}
	panic("illegal value")
}

// Defines the allowed kinds of exports.
const (
	FunctionExportType ExportDescriptorType = iota
	TableExportType
	MemoryExportType
	GlobalExportType
)

func (x ExportDescriptorType) String() string {
	switch x {
	case FunctionExportType:
		return "func"
	case TableExportType:
		return "table"
	case MemoryExportType:
		return "memory"
	case GlobalExportType:
		return "global"
	}
	panic("illegal value")
}

// Kind returns the function import type kind.
func (i FunctionImport) Kind() ImportDescriptorType {
	return FunctionImportType
}

func (i FunctionImport) String() string {
	return fmt.Sprintf("%v[type=%v]", i.Kind(), i.Func)
}

// Kind returns the memory import type kind.
func (i MemoryImport) Kind() ImportDescriptorType {
	return MemoryImportType
}

func (i MemoryImport) String() string {
	return fmt.Sprintf("%v[%v]", i.Kind(), i.Mem.Lim)
}

// Kind returns the table import type kind.
func (i TableImport) Kind() ImportDescriptorType {
	return TableImportType
}

func (i TableImport) String() string {
	return fmt.Sprintf("%v[%v, %v]", i.Kind(), i.Type, i.Lim)
}

// Kind returns the global import type kind.
func (i GlobalImport) Kind() ImportDescriptorType {
	return GlobalImportType
}

func (i GlobalImport) String() string {
	return fmt.Sprintf("%v[%v, mut=%v]", i.Kind(), i.Type, i.Mutable)
}

func (tpe FunctionType) String() string {
	params := make([]string, len(tpe.Params))
	results := make([]string, len(tpe.Results))
	for i := range tpe.Params {
		params[i] = tpe.Params[i].String()
	}
	for i := range tpe.Results {
		results[i] = tpe.Results[i].String()
	}
	return "(" + strings.Join(params, ", ") + ") -> (" + strings.Join(results, ", ") + ")"
}

// Equal returns true if tpe equals other.
func (tpe FunctionType) Equal(other FunctionType) bool {

	if len(tpe.Params) != len(other.Params) || len(tpe.Results) != len(other.Results) {
		return false
	}

	for i := range tpe.Params {
		if tpe.Params[i] != other.Params[i] {
			return false
		}
	}

	for i := range tpe.Results {
		if tpe.Results[i] != other.Results[i] {
			return false
		}
	}

	return true
}

func (imp Import) String() string {
	return fmt.Sprintf("%v %v.%v", imp.Descriptor.String(), imp.Module, imp.Name)
}

func (exp Export) String() string {
	return fmt.Sprintf("%v[%v] %v", exp.Descriptor.Type, exp.Descriptor.Index, exp.Name)
}

func (seg RawCodeSegment) String() string {
	return fmt.Sprintf("<code %d bytes>", len(seg.Code))
}

func (seg DataSegment) String() string {
	return fmt.Sprintf("<data index=%v [%v] len=%d bytes>", seg.Index, seg.Offset, len(seg.Init))
}

func (e Expr) String() string {
	return fmt.Sprintf("%d instr(s)", len(e.Instrs))
}

func (lim Limit) String() string {
	if lim.Max == nil {
		return fmt.Sprintf("min=%v", lim.Min)
	}
	return fmt.Sprintf("min=%v max=%v", lim.Min, lim.Max)
}
