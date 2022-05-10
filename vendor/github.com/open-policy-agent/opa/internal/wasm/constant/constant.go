// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package constant contains WASM constant definitions.
package constant

// Magic bytes at the beginning of every WASM file ("\0asm").
const Magic = uint32(0x6D736100)

// Version defines the WASM version.
const Version = uint32(1)

// WASM module section IDs.
const (
	CustomSectionID uint8 = iota
	TypeSectionID
	ImportSectionID
	FunctionSectionID
	TableSectionID
	MemorySectionID
	GlobalSectionID
	ExportSectionID
	StartSectionID
	ElementSectionID
	CodeSectionID
	DataSectionID
)

// FunctionTypeID indicates the start of a function type definition.
const FunctionTypeID = byte(0x60)

// ValueType represents an intrinsic value type in WASM.
const (
	ValueTypeF64 byte = iota + 0x7C
	ValueTypeF32
	ValueTypeI64
	ValueTypeI32
)

// WASM import descriptor types.
const (
	ImportDescType byte = iota
	ImportDescTable
	ImportDescMem
	ImportDescGlobal
)

// WASM export descriptor types.
const (
	ExportDescType byte = iota
	ExportDescTable
	ExportDescMem
	ExportDescGlobal
)

// ElementTypeAnyFunc indicates the type of a table import.
const ElementTypeAnyFunc byte = 0x70

// BlockTypeEmpty represents a block type.
const BlockTypeEmpty byte = 0x40

// WASM global varialbe mutability flag.
const (
	Const byte = iota
	Mutable
)

// NameSectionCustomID is the ID of the "Name" section Custom Section
const NameSectionCustomID = "name"

// Subtypes of the 'name' custom section
const (
	NameSectionModuleType byte = iota
	NameSectionFunctionsType
	NameSectionLocalsType
)
