// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package wasm contains an IR->WASM compiler backend.
package wasm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/pkg/errors"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/internal/compiler/wasm/opa"
	"github.com/open-policy-agent/opa/internal/debug"
	"github.com/open-policy-agent/opa/internal/ir"
	"github.com/open-policy-agent/opa/internal/wasm/encoding"
	"github.com/open-policy-agent/opa/internal/wasm/instruction"
	"github.com/open-policy-agent/opa/internal/wasm/module"
	"github.com/open-policy-agent/opa/internal/wasm/types"
	"github.com/open-policy-agent/opa/internal/wasm/util"
	opatypes "github.com/open-policy-agent/opa/types"
)

// Record Wasm ABI version in exported global variable
const (
	opaWasmABIVersionVal      = 1
	opaWasmABIVersionVar      = "opa_wasm_abi_version"
	opaWasmABIMinorVersionVal = 2
	opaWasmABIMinorVersionVar = "opa_wasm_abi_minor_version"
)

// nolint: deadcode,varcheck
const (
	opaTypeNull int32 = iota + 1
	opaTypeBoolean
	opaTypeNumber
	opaTypeString
	opaTypeArray
	opaTypeObject
	opaTypeSet
	opaTypeStringInterned
	opaTypeBooleanInterned
)

const (
	opaAbort             = "opa_abort"
	opaRuntimeError      = "opa_runtime_error"
	opaNull              = "opa_null"
	opaBoolean           = "opa_boolean"
	opaNumberInt         = "opa_number_int"
	opaNumberRef         = "opa_number_ref"
	opaNumberSize        = "opa_number_size"
	opaArrayWithCap      = "opa_array_with_cap"
	opaArrayAppend       = "opa_array_append"
	opaObject            = "opa_object"
	opaObjectInsert      = "opa_object_insert"
	opaSet               = "opa_set"
	opaSetAdd            = "opa_set_add"
	opaStringTerminated  = "opa_string_terminated"
	opaValueNumberSetInt = "opa_value_number_set_int"
	opaValueCompare      = "opa_value_compare"
	opaValueGet          = "opa_value_get"
	opaValueIter         = "opa_value_iter"
	opaValueLength       = "opa_value_length"
	opaValueMerge        = "opa_value_merge"
	opaValueShallowCopy  = "opa_value_shallow_copy"
	opaValueType         = "opa_value_type"
	opaMemoizeInit       = "opa_memoize_init"
	opaMemoizePush       = "opa_memoize_push"
	opaMemoizePop        = "opa_memoize_pop"
	opaMemoizeInsert     = "opa_memoize_insert"
	opaMemoizeGet        = "opa_memoize_get"
	opaMappingInit       = "opa_mapping_init"
	opaMappingLookup     = "opa_mapping_lookup"
	opaMPDInit           = "opa_mpd_init"
	opaMallocInit        = "opa_malloc_init"
)

var builtinsFunctions = map[string]string{
	ast.Plus.Name:                       "opa_arith_plus",
	ast.Minus.Name:                      "opa_arith_minus",
	ast.Multiply.Name:                   "opa_arith_multiply",
	ast.Divide.Name:                     "opa_arith_divide",
	ast.Abs.Name:                        "opa_arith_abs",
	ast.Round.Name:                      "opa_arith_round",
	ast.Ceil.Name:                       "opa_arith_ceil",
	ast.Floor.Name:                      "opa_arith_floor",
	ast.Rem.Name:                        "opa_arith_rem",
	ast.ArrayConcat.Name:                "opa_array_concat",
	ast.ArrayReverse.Name:               "opa_array_reverse",
	ast.ArraySlice.Name:                 "opa_array_slice",
	ast.SetDiff.Name:                    "opa_set_diff",
	ast.And.Name:                        "opa_set_intersection",
	ast.Or.Name:                         "opa_set_union",
	ast.Intersection.Name:               "opa_sets_intersection",
	ast.Union.Name:                      "opa_sets_union",
	ast.IsNumber.Name:                   "opa_types_is_number",
	ast.IsString.Name:                   "opa_types_is_string",
	ast.IsBoolean.Name:                  "opa_types_is_boolean",
	ast.IsArray.Name:                    "opa_types_is_array",
	ast.IsSet.Name:                      "opa_types_is_set",
	ast.IsObject.Name:                   "opa_types_is_object",
	ast.IsNull.Name:                     "opa_types_is_null",
	ast.TypeNameBuiltin.Name:            "opa_types_name",
	ast.BitsOr.Name:                     "opa_bits_or",
	ast.BitsAnd.Name:                    "opa_bits_and",
	ast.BitsNegate.Name:                 "opa_bits_negate",
	ast.BitsXOr.Name:                    "opa_bits_xor",
	ast.BitsShiftLeft.Name:              "opa_bits_shiftleft",
	ast.BitsShiftRight.Name:             "opa_bits_shiftright",
	ast.Count.Name:                      "opa_agg_count",
	ast.Sum.Name:                        "opa_agg_sum",
	ast.Product.Name:                    "opa_agg_product",
	ast.Max.Name:                        "opa_agg_max",
	ast.Min.Name:                        "opa_agg_min",
	ast.Sort.Name:                       "opa_agg_sort",
	ast.All.Name:                        "opa_agg_all",
	ast.Any.Name:                        "opa_agg_any",
	ast.Base64IsValid.Name:              "opa_base64_is_valid",
	ast.Base64Decode.Name:               "opa_base64_decode",
	ast.Base64Encode.Name:               "opa_base64_encode",
	ast.Base64UrlEncode.Name:            "opa_base64_url_encode",
	ast.Base64UrlDecode.Name:            "opa_base64_url_decode",
	ast.NetCIDRContains.Name:            "opa_cidr_contains",
	ast.NetCIDROverlap.Name:             "opa_cidr_contains",
	ast.NetCIDRIntersects.Name:          "opa_cidr_intersects",
	ast.Equal.Name:                      "opa_cmp_eq",
	ast.GreaterThan.Name:                "opa_cmp_gt",
	ast.GreaterThanEq.Name:              "opa_cmp_gte",
	ast.LessThan.Name:                   "opa_cmp_lt",
	ast.LessThanEq.Name:                 "opa_cmp_lte",
	ast.NotEqual.Name:                   "opa_cmp_neq",
	ast.GlobMatch.Name:                  "opa_glob_match",
	ast.JSONMarshal.Name:                "opa_json_marshal",
	ast.JSONUnmarshal.Name:              "opa_json_unmarshal",
	ast.JSONIsValid.Name:                "opa_json_is_valid",
	ast.ObjectFilter.Name:               "builtin_object_filter",
	ast.ObjectGet.Name:                  "builtin_object_get",
	ast.ObjectRemove.Name:               "builtin_object_remove",
	ast.ObjectUnion.Name:                "builtin_object_union",
	ast.Concat.Name:                     "opa_strings_concat",
	ast.FormatInt.Name:                  "opa_strings_format_int",
	ast.IndexOf.Name:                    "opa_strings_indexof",
	ast.Substring.Name:                  "opa_strings_substring",
	ast.Lower.Name:                      "opa_strings_lower",
	ast.Upper.Name:                      "opa_strings_upper",
	ast.Contains.Name:                   "opa_strings_contains",
	ast.StartsWith.Name:                 "opa_strings_startswith",
	ast.EndsWith.Name:                   "opa_strings_endswith",
	ast.StringReverse.Name:              "opa_strings_reverse",
	ast.Split.Name:                      "opa_strings_split",
	ast.Replace.Name:                    "opa_strings_replace",
	ast.ReplaceN.Name:                   "opa_strings_replace_n",
	ast.Trim.Name:                       "opa_strings_trim",
	ast.TrimLeft.Name:                   "opa_strings_trim_left",
	ast.TrimPrefix.Name:                 "opa_strings_trim_prefix",
	ast.TrimRight.Name:                  "opa_strings_trim_right",
	ast.TrimSuffix.Name:                 "opa_strings_trim_suffix",
	ast.TrimSpace.Name:                  "opa_strings_trim_space",
	ast.NumbersRange.Name:               "opa_numbers_range",
	ast.ToNumber.Name:                   "opa_to_number",
	ast.WalkBuiltin.Name:                "opa_value_transitive_closure",
	ast.ReachableBuiltin.Name:           "builtin_graph_reachable",
	ast.RegexIsValid.Name:               "opa_regex_is_valid",
	ast.RegexMatch.Name:                 "opa_regex_match",
	ast.RegexMatchDeprecated.Name:       "opa_regex_match",
	ast.RegexFindAllStringSubmatch.Name: "opa_regex_find_all_string_submatch",
	ast.JSONRemove.Name:                 "builtin_json_remove",
	ast.JSONFilter.Name:                 "builtin_json_filter",
	ast.Member.Name:                     "builtin_member",
	ast.MemberWithKey.Name:              "builtin_member3",
}

// If none of these is called from a policy, the resulting wasm
// module will not contain any RE2-related functions
var builtinsUsingRE2 = [...]string{
	builtinsFunctions[ast.RegexIsValid.Name],
	builtinsFunctions[ast.RegexMatch.Name],
	builtinsFunctions[ast.RegexMatchDeprecated.Name],
	builtinsFunctions[ast.RegexFindAllStringSubmatch.Name],
	builtinsFunctions[ast.GlobMatch.Name],
}

type externalFunc struct {
	ID   int32
	Decl *opatypes.Function
}

var builtinDispatchers = [...]string{
	"opa_builtin0",
	"opa_builtin1",
	"opa_builtin2",
	"opa_builtin3",
	"opa_builtin4",
}

// Compiler implements an IR->WASM compiler backend.
type Compiler struct {
	stages []func() error // compiler stages to execute
	errors []error        // compilation errors encountered

	policy *ir.Policy        // input policy to compile
	module *module.Module    // output WASM module
	code   *module.CodeEntry // output WASM code

	funcsCode []funcCode // compile functions' code

	builtinStringAddrs    map[int]uint32          // addresses of built-in string constants
	externalFuncNameAddrs map[string]int32        // addresses of required built-in function names for listing
	externalFuncs         map[string]externalFunc // required built-in function ids and types
	entrypointNameAddrs   map[string]int32        // addresses of available entrypoint names for listing
	entrypoints           map[string]int32        // available entrypoint ids
	stringOffset          int32                   // null-terminated string data base offset
	stringAddrs           []uint32                // null-terminated string constant addresses
	opaStringAddrs        []uint32                // addresses of interned opa_string_t
	opaBoolAddrs          map[ir.Bool]uint32      // addresses of interned opa_boolean_t
	fileAddrs             []uint32                // null-terminated string constant addresses, used for file names
	funcs                 map[string]uint32       // maps imported and exported function names to function indices

	nextLocal uint32
	locals    map[ir.Local]uint32
	lctx      uint32 // local pointing to eval context
	lrs       uint32 // local pointing to result set

	debug debug.Debug
}

type funcCode struct {
	name string
	code *module.CodeEntry
}

const (
	errVarAssignConflict int = iota
	errObjectInsertConflict
	errIllegalEntrypoint
)

var errorMessages = [...]struct {
	id      int
	message string
}{
	{errVarAssignConflict, "var assignment conflict"},
	{errObjectInsertConflict, "object insert conflict"},
	{errIllegalEntrypoint, "internal: illegal entrypoint id"},
}

// New returns a new compiler object.
func New() *Compiler {
	c := &Compiler{
		debug: debug.Discard(),
	}
	c.stages = []func() error{
		c.initModule,
		c.compileStringsAndBooleans,
		c.addImportMemoryDecl,
		c.compileExternalFuncDecls,
		c.compileEntrypointDecls,
		c.compileFuncs,
		c.compilePlans,
		c.emitABIVersionGlobals,

		// "local" optimizations
		c.removeUnusedCode,

		// final emissions
		c.emitFuncs,

		// global optimizations
		c.optimizeBinaryen,
	}
	return c
}

// ABIVersion returns the Wasm ABI version this compiler
// emits.
func (*Compiler) ABIVersion() ast.WasmABIVersion {
	return ast.WasmABIVersion{
		Version: opaWasmABIVersionVal,
		Minor:   opaWasmABIMinorVersionVal,
	}
}

// WithPolicy sets the policy to compile.
func (c *Compiler) WithPolicy(p *ir.Policy) *Compiler {
	c.policy = p
	return c
}

// WithDebug sets the sink for debug logs emitted by the compiler.
func (c *Compiler) WithDebug(sink io.Writer) *Compiler {
	if sink != nil {
		c.debug = debug.New(sink)
	}
	return c
}

// Compile returns a compiled WASM module.
func (c *Compiler) Compile() (*module.Module, error) {

	for _, stage := range c.stages {
		if err := stage(); err != nil {
			return nil, err
		} else if len(c.errors) > 0 {
			return nil, c.errors[0] // TODO(tsandall) return all errors.
		}
	}

	return c.module, nil
}

// initModule instantiates the module from the pre-compiled OPA binary. The
// module is then updated to include declarations for all of the functions that
// are about to be compiled.
func (c *Compiler) initModule() error {

	bs, err := opa.Bytes()
	if err != nil {
		return err
	}

	c.module, err = encoding.ReadModule(bytes.NewReader(bs))
	if err != nil {
		return err
	}

	c.funcs = make(map[string]uint32)
	for _, fn := range c.module.Names.Functions {
		name := fn.Name
		// Account for recording duplicate functions -- this only happens
		// with the RE2 C++ lib so far.
		// NOTE: This isn't good enough for function names used more than
		// two times. But let's deal with that when it happens.
		if _, ok := c.funcs[name]; ok { // already seen
			c.debug.Printf("function name duplicate: %s (%d)", name, fn.Index)
			name = name + ".1"
		}
		c.funcs[name] = fn.Index
	}

	for _, fn := range c.policy.Funcs.Funcs {

		params := make([]types.ValueType, len(fn.Params))
		for i := 0; i < len(params); i++ {
			params[i] = types.I32
		}

		tpe := module.FunctionType{
			Params:  params,
			Results: []types.ValueType{types.I32},
		}

		c.emitFunctionDecl(fn.Name, tpe, false)
	}

	c.emitFunctionDecl("eval", module.FunctionType{
		Params:  []types.ValueType{types.I32},
		Results: []types.ValueType{types.I32},
	}, true)

	c.emitFunctionDecl("builtins", module.FunctionType{
		Params:  nil,
		Results: []types.ValueType{types.I32},
	}, true)

	c.emitFunctionDecl("entrypoints", module.FunctionType{
		Params:  nil,
		Results: []types.ValueType{types.I32},
	}, true)

	// NOTE(sr): LLVM needs a section of linear memory to be zero'ed out and reserved,
	// for static variables defined in the C code. When using imported memory, it adds
	// a data segment to ensure that. When not using imported memory, it would ensure
	// that a zero'ed out region is available by adjust the __heap_base address.
	// Since we control "imported/not-imported" memory here, we make these adjustments
	// here, too:
	//
	// a. the __heap_base exported variable is read,
	// b. the __heap_base variable is removed from exports and globals
	// c. a data segment filled with zeros of the proper length is added
	var idx uint32
	var del int
	for i, exp := range c.module.Export.Exports {
		if exp.Name == "__heap_base" {
			idx = exp.Descriptor.Index
			del = i
		}
	}
	heapBase := c.module.Global.Globals[idx].Init.Instrs[0].(instruction.I32Const).Value

	// (b) remove __heap_base export and global
	c.module.Export.Exports = append(c.module.Export.Exports[:del], c.module.Export.Exports[del+1:]...)
	c.module.Global.Globals = append(c.module.Global.Globals[:idx], c.module.Global.Globals[idx+1:]...)

	// (c) add data segment with zeros
	offset, err := getLowestFreeDataSegmentOffset(c.module)
	if err != nil {
		return err
	}

	c.module.Data.Segments = append(c.module.Data.Segments, module.DataSegment{
		Index: 0,
		Offset: module.Expr{
			Instrs: []instruction.Instruction{
				instruction.I32Const{
					Value: offset,
				},
			},
		},
		Init: bytes.Repeat([]byte{0}, int(heapBase-offset)),
	})

	return nil
}

// NOTE(sr): The wasm module we start with, compiled via LLVM, has NO memory
// import or export. Here, we change that: the OPA-generated wasm module will
//
// a. import its memory
// b. re-export that memory
// c. have no "own" memory (in its memory section)
//
// (b) is provided by the LLVM base module, it already has an export of memory[0]
// (a) and (c) are taken care of here.
//
// In the future, we could change that, and here would be the place to do so.
func (c *Compiler) addImportMemoryDecl() error {
	offset, err := getLowestFreeDataSegmentOffset(c.module)
	if err != nil {
		return err
	}

	c.module.Import.Imports = append(c.module.Import.Imports, module.Import{
		Module: "env",
		Name:   "memory",
		Descriptor: module.MemoryImport{
			Mem: module.MemType{
				Lim: module.Limit{
					Min: util.Pages(uint32(offset)),
				},
			},
		},
	})
	c.module.Memory.Memories = nil

	return nil
}

// emitABIVersionGLobals adds globals for ABI [minor] version, exports them
func (c *Compiler) emitABIVersionGlobals() error {
	abiVersionGlobals := []module.Global{
		{
			Type:    types.I32,
			Mutable: false,
			Init: module.Expr{
				Instrs: []instruction.Instruction{
					instruction.I32Const{Value: opaWasmABIVersionVal},
				},
			},
		},
		{
			Type:    types.I32,
			Mutable: false,
			Init: module.Expr{
				Instrs: []instruction.Instruction{
					instruction.I32Const{Value: opaWasmABIMinorVersionVal},
				},
			},
		},
	}
	abiVersionExports := []module.Export{
		{
			Name: opaWasmABIVersionVar,
			Descriptor: module.ExportDescriptor{
				Type:  module.GlobalExportType,
				Index: uint32(len(c.module.Global.Globals)),
			},
		},
		{
			Name: opaWasmABIMinorVersionVar,
			Descriptor: module.ExportDescriptor{
				Type:  module.GlobalExportType,
				Index: uint32(len(c.module.Global.Globals)) + 1,
			},
		},
	}
	c.module.Global.Globals = append(c.module.Global.Globals, abiVersionGlobals...)
	c.module.Export.Exports = append(c.module.Export.Exports, abiVersionExports...)
	return nil
}

// compileStringsAndBooleans compiles various string constants (strings, file names,
// external function names, entrypoint names, builtin names), and interned opa_value structs
// for strings and booleans into the data section of the module.
// All are indexed for lookups in later stages.
func (c *Compiler) compileStringsAndBooleans() error {

	var err error
	c.stringOffset, err = getLowestFreeDataSegmentOffset(c.module)
	if err != nil {
		return err
	}

	var buf bytes.Buffer

	c.writeStrings(&buf)

	if err := c.writeInternedOPAValues(&buf); err != nil {
		return err
	}

	c.writeFileAddrs(&buf)
	c.writeExternalFuncNames(&buf)
	c.writeEntrypointNames(&buf)
	c.writeBuiltinStrings(&buf)

	c.module.Data.Segments = append(c.module.Data.Segments, module.DataSegment{
		Index: 0,
		Offset: module.Expr{
			Instrs: []instruction.Instruction{
				instruction.I32Const{
					Value: c.stringOffset,
				},
			},
		},
		Init: buf.Bytes(),
	})

	return nil
}

func (c *Compiler) writeStrings(buf *bytes.Buffer) {
	c.stringAddrs = make([]uint32, len(c.policy.Static.Strings))

	for i, s := range c.policy.Static.Strings {
		addr := uint32(buf.Len()) + uint32(c.stringOffset)
		buf.WriteString(s.Value)
		buf.WriteByte(0)
		c.stringAddrs[i] = addr
	}
}

func (c *Compiler) writeInternedOPAValues(buf *bytes.Buffer) error {
	// interned `opa_value*` for these true/false booleans
	c.opaBoolAddrs = make(map[ir.Bool]uint32, 2)
	for _, val := range []bool{true, false} {
		opaBool := ir.Bool(val)
		v := byte(0)
		if val {
			v = 1
		}
		c.opaBoolAddrs[opaBool] = uint32(buf.Len()) + uint32(c.stringOffset)
		size := 2
		n, err := buf.Write([]byte{byte(opaTypeBooleanInterned), v})
		if err != nil {
			return fmt.Errorf("write interned bools: %w", err)
		}
		if n != size {
			return fmt.Errorf("short write: %d (expected %d)", n, size)
		}
	}

	// interned `opa_value*` for these constant strings
	c.opaStringAddrs = make([]uint32, len(c.policy.Static.Strings))
	for i, s := range c.policy.Static.Strings {
		c.opaStringAddrs[i] = uint32(buf.Len()) + uint32(c.stringOffset)
		size := 12
		b := make([]byte, size)
		binary.LittleEndian.PutUint16(b[0:], uint16(opaTypeStringInterned))
		binary.LittleEndian.PutUint32(b[4:], uint32(len(s.Value)))
		binary.LittleEndian.PutUint32(b[8:], c.stringAddrs[i])
		n, err := buf.Write(b)
		if err != nil {
			return fmt.Errorf("write interned strings: %w", err)
		}
		if n != size {
			return fmt.Errorf("short write: %d (expected %d)", n, size)
		}
	}
	return nil
}

func (c *Compiler) writeFileAddrs(buf *bytes.Buffer) {
	// NOTE(sr): All files that have been consulted in planning are recorded,
	// regardless of their potential in generating runtime errors.
	c.fileAddrs = make([]uint32, len(c.policy.Static.Files))

	for i, file := range c.policy.Static.Files {
		addr := uint32(buf.Len()) + uint32(c.stringOffset)
		buf.WriteString(file.Value)
		buf.WriteByte(0)
		c.fileAddrs[i] = addr
	}
}

func (c *Compiler) writeExternalFuncNames(buf *bytes.Buffer) {
	c.externalFuncNameAddrs = make(map[string]int32)

	for _, decl := range c.policy.Static.BuiltinFuncs {
		if _, ok := builtinsFunctions[decl.Name]; !ok {
			addr := int32(buf.Len()) + int32(c.stringOffset)
			buf.WriteString(decl.Name)
			buf.WriteByte(0)
			c.externalFuncNameAddrs[decl.Name] = addr
		}
	}
}

func (c *Compiler) writeEntrypointNames(buf *bytes.Buffer) {
	c.entrypointNameAddrs = make(map[string]int32)

	for _, plan := range c.policy.Plans.Plans {
		addr := int32(buf.Len()) + int32(c.stringOffset)
		buf.WriteString(plan.Name)
		buf.WriteByte(0)
		c.entrypointNameAddrs[plan.Name] = addr
	}
}

func (c *Compiler) writeBuiltinStrings(buf *bytes.Buffer) {
	c.builtinStringAddrs = make(map[int]uint32, len(errorMessages))

	for i := range errorMessages {
		addr := uint32(buf.Len()) + uint32(c.stringOffset)
		buf.WriteString(errorMessages[i].message)
		buf.WriteByte(0)
		c.builtinStringAddrs[errorMessages[i].id] = addr
	}
}

// compileExternalFuncDecls generates a function that lists the built-ins required by
// the policy. The host environment should invoke this function obtain the list
// of built-in function identifiers (represented as integers) that will be used
// when calling out.
func (c *Compiler) compileExternalFuncDecls() error {

	c.code = &module.CodeEntry{}
	c.nextLocal = 0
	c.locals = map[ir.Local]uint32{}

	lobj := c.genLocal()

	c.appendInstr(instruction.Call{Index: c.function(opaObject)})
	c.appendInstr(instruction.SetLocal{Index: lobj})
	c.externalFuncs = make(map[string]externalFunc)

	for index, decl := range c.policy.Static.BuiltinFuncs {
		if _, ok := builtinsFunctions[decl.Name]; !ok {
			c.appendInstr(instruction.GetLocal{Index: lobj})
			c.appendInstr(instruction.I32Const{Value: c.externalFuncNameAddrs[decl.Name]})
			c.appendInstr(instruction.Call{Index: c.function(opaStringTerminated)})
			c.appendInstr(instruction.I64Const{Value: int64(index)})
			c.appendInstr(instruction.Call{Index: c.function(opaNumberInt)})
			c.appendInstr(instruction.Call{Index: c.function(opaObjectInsert)})
			c.externalFuncs[decl.Name] = externalFunc{ID: int32(index), Decl: decl.Decl}
		}
	}

	c.appendInstr(instruction.GetLocal{Index: lobj})

	c.code.Func.Locals = []module.LocalDeclaration{
		{
			Count: c.nextLocal,
			Type:  types.I32,
		},
	}

	return c.storeFunc("builtins", c.code)
}

// compileEntrypointDecls generates a function that lists the entrypoints available
// in the policy. The host environment can pick which entrypoint to invoke by setting
// the entrypoint identifier (represented as an integer) on the evaluation context.
func (c *Compiler) compileEntrypointDecls() error {

	c.code = &module.CodeEntry{}
	c.nextLocal = 0
	c.locals = map[ir.Local]uint32{}

	lobj := c.genLocal()

	c.appendInstr(instruction.Call{Index: c.function(opaObject)})
	c.appendInstr(instruction.SetLocal{Index: lobj})
	c.entrypoints = make(map[string]int32)

	for index, plan := range c.policy.Plans.Plans {
		c.appendInstr(instruction.GetLocal{Index: lobj})
		c.appendInstr(instruction.I32Const{Value: c.entrypointNameAddrs[plan.Name]})
		c.appendInstr(instruction.Call{Index: c.function(opaStringTerminated)})
		c.appendInstr(instruction.I64Const{Value: int64(index)})
		c.appendInstr(instruction.Call{Index: c.function(opaNumberInt)})
		c.appendInstr(instruction.Call{Index: c.function(opaObjectInsert)})
		c.entrypoints[plan.Name] = int32(index)
	}

	c.appendInstr(instruction.GetLocal{Index: lobj})

	c.code.Func.Locals = []module.LocalDeclaration{
		{
			Count: c.nextLocal,
			Type:  types.I32,
		},
	}

	return c.storeFunc("entrypoints", c.code)
}

// compileFuncs compiles the policy functions and emits them into the module.
func (c *Compiler) compileFuncs() error {
	for _, fn := range c.policy.Funcs.Funcs {
		if err := c.compileFunc(fn); err != nil {
			return fmt.Errorf("func %v: %w", fn.Name, err)
		}
	}

	if err := c.emitMappingAndStartFunc(); err != nil {
		return fmt.Errorf("writing mapping: %w", err)
	}

	if err := c.replaceBooleanFunc(); err != nil {
		return fmt.Errorf("replacing opa_boolean: %w", err)
	}
	return nil
}

// compilePlans compiles the policy plans and emits the resulting function into
// the module.
func (c *Compiler) compilePlans() error {

	c.code = &module.CodeEntry{}
	c.nextLocal = 0
	c.locals = map[ir.Local]uint32{}
	c.lctx = c.genLocal()
	c.lrs = c.genLocal()

	// Initialize memoization.
	c.appendInstr(instruction.Call{Index: c.function(opaMemoizeInit)})

	// Initialize the input and data locals.
	c.appendInstr(instruction.GetLocal{Index: c.lctx})
	c.appendInstr(instruction.I32Load{Offset: 0, Align: 2})
	c.appendInstr(instruction.SetLocal{Index: c.local(ir.Input)})

	c.appendInstr(instruction.GetLocal{Index: c.lctx})
	c.appendInstr(instruction.I32Load{Offset: 4, Align: 2})
	c.appendInstr(instruction.SetLocal{Index: c.local(ir.Data)})

	// Initialize the result set.
	c.appendInstr(instruction.Call{Index: c.function(opaSet)})
	c.appendInstr(instruction.SetLocal{Index: c.lrs})
	c.appendInstr(instruction.GetLocal{Index: c.lctx})
	c.appendInstr(instruction.GetLocal{Index: c.lrs})
	c.appendInstr(instruction.I32Store{Offset: 8, Align: 2})

	// Initialize the entrypoint id local.
	leid := c.genLocal()
	c.appendInstr(instruction.GetLocal{Index: c.lctx})
	c.appendInstr(instruction.I32Load{Offset: 12, Align: 2})
	c.appendInstr(instruction.SetLocal{Index: leid})

	// Add each entrypoint to this block.
	main := instruction.Block{}

	for i, plan := range c.policy.Plans.Plans {

		entrypoint := instruction.Block{
			Instrs: []instruction.Instruction{
				instruction.GetLocal{Index: leid},
				instruction.I32Const{Value: int32(i)},
				instruction.I32Ne{},
				instruction.BrIf{Index: 0},
			},
		}

		for j, block := range plan.Blocks {

			instrs, err := c.compileBlock(block)
			if err != nil {
				return fmt.Errorf("plan %d block %d: %w", i, j, err)
			}

			entrypoint.Instrs = append(entrypoint.Instrs, instruction.Block{
				Instrs: instrs,
			})
		}

		entrypoint.Instrs = append(entrypoint.Instrs, instruction.Br{Index: 1})
		main.Instrs = append(main.Instrs, entrypoint)
	}

	// If none of the entrypoint blocks execute, call opa_abort() as this likely
	// indicates inconsistency between the generated entrypoint identifiers in the
	// eval() and entrypoint() functions (or the SDK invoked eval() with an invalid
	// entrypoint ID which should not be possible.)
	main.Instrs = append(main.Instrs,
		instruction.I32Const{Value: c.builtinStringAddr(errIllegalEntrypoint)},
		instruction.Call{Index: c.function(opaAbort)},
		instruction.Unreachable{},
	)

	c.appendInstr(main)
	c.appendInstr(instruction.I32Const{Value: int32(0)})

	c.code.Func.Locals = []module.LocalDeclaration{
		{
			Count: c.nextLocal,
			Type:  types.I32,
		},
	}

	return c.storeFunc("eval", c.code)
}

func (c *Compiler) compileFunc(fn *ir.Func) error {
	idx, ok := c.funcs[fn.Name]
	if !ok {
		return fmt.Errorf("unknown function: %v", fn.Name)
	}

	memoize := len(fn.Params) == 2

	if len(fn.Params) == 0 {
		return fmt.Errorf("illegal function: zero args")
	}

	c.nextLocal = 0
	c.locals = map[ir.Local]uint32{}

	for _, a := range fn.Params {
		_ = c.local(a)
	}

	_ = c.local(fn.Return)

	c.code = &module.CodeEntry{}

	// memoization: get
	if memoize {
		c.appendInstr(instruction.I32Const{Value: int32(idx)})
		c.appendInstr(instruction.Call{Index: c.function(opaMemoizeGet)})
		c.appendInstr(instruction.TeeLocal{Index: c.local(fn.Return)})
		c.appendInstr(instruction.If{Instrs: []instruction.Instruction{
			instruction.GetLocal{Index: c.local(fn.Return)},
			instruction.Return{},
		}})
	}

	for i := range fn.Blocks {
		instrs, err := c.compileBlock(fn.Blocks[i])
		if err != nil {
			return errors.Wrapf(err, "block %d", i)
		}
		if i < len(fn.Blocks)-1 { // not the last block: wrap in `block` instr
			if withControlInstr(instrs) { // unless we don't need to
				c.appendInstr(instruction.Block{Instrs: instrs})
			} else {
				c.appendInstrs(instrs)
			}
		} else { // last block, no wrapping
			// memoization: insert, spliced into the instructions right
			// before the return:
			for _, instr := range instrs {
				if _, ok := instr.(instruction.Return); ok && memoize {
					c.appendInstr(instruction.I32Const{Value: int32(idx)})
					c.appendInstr(instruction.GetLocal{Index: c.local(fn.Return)})
					c.appendInstr(instruction.Call{Index: c.function(opaMemoizeInsert)})
				}
				c.appendInstr(instr)
			}
		}
	}

	c.code.Func.Locals = []module.LocalDeclaration{
		{
			Count: c.nextLocal,
			Type:  types.I32,
		},
	}

	return c.storeFunc(fn.Name, c.code)
}

func mapFunc(mapping ast.Object, fn *ir.Func, index int) (ast.Object, bool) {
	curr := ast.NewObject()
	curr.Insert(ast.StringTerm(fn.Path[len(fn.Path)-1]), ast.IntNumberTerm(index))
	for i := len(fn.Path) - 2; i >= 0; i-- {
		o := ast.NewObject()
		o.Insert(ast.StringTerm(fn.Path[i]), ast.NewTerm(curr))
		curr = o
	}
	return mapping.Merge(curr)
}

func (c *Compiler) emitMappingAndStartFunc() error {
	var indices []uint32
	var ok bool
	mapping := ast.NewObject()

	// element segment offset for our mapped function entries
	elemOffset, err := getLowestFreeElementSegmentOffset(c.module)
	if err != nil {
		return err
	}

	for i, fn := range c.policy.Funcs.Funcs {
		indices = append(indices, c.funcs[fn.Name])
		mapping, ok = mapFunc(mapping, fn, i+int(elemOffset))
		if !ok {
			return fmt.Errorf("mapping function %v failed", fn.Name)
		}
	}

	// emit data segment for JSON blob encoding mapping
	jsonMap := []byte(mapping.String())
	dataOffset, err := getLowestFreeDataSegmentOffset(c.module)
	if err != nil {
		return err
	}
	c.module.Data.Segments = append(c.module.Data.Segments, module.DataSegment{
		Index: 0,
		Offset: module.Expr{
			Instrs: []instruction.Instruction{
				instruction.I32Const{
					Value: dataOffset,
				},
			},
		},
		Init: jsonMap,
	})

	// write element segments for table entries
	c.module.Element.Segments = append(c.module.Element.Segments, module.ElementSegment{
		Index: 0,
		Offset: module.Expr{
			Instrs: []instruction.Instruction{
				instruction.I32Const{
					Value: elemOffset,
				},
			},
		},
		Indices: indices,
	})

	// adjust table limits
	min := c.module.Table.Tables[0].Lim.Min + uint32(len(indices))
	max := *c.module.Table.Tables[0].Lim.Max + uint32(len(indices))
	c.module.Table.Tables[0].Lim.Min = min
	c.module.Table.Tables[0].Lim.Max = &max

	heapBase, err := getLowestFreeDataSegmentOffset(c.module)
	if err != nil {
		return err
	}

	// create function that calls `void opa_mapping_initialize(const char *s, const int l)`
	// with s being the offset of the data segment just written, and l its length
	fName := "_initialize"
	c.code = &module.CodeEntry{}
	c.appendInstr(instruction.I32Const{Value: heapBase})
	c.appendInstr(instruction.Call{Index: c.function(opaMallocInit)})
	c.appendInstr(instruction.Call{Index: c.function(opaMPDInit)})
	c.appendInstr(instruction.I32Const{Value: dataOffset})
	c.appendInstr(instruction.I32Const{Value: int32(len(jsonMap))})
	c.appendInstr(instruction.Call{Index: c.function(opaMappingInit)})
	c.emitFunctionDecl(fName, module.FunctionType{}, false)
	idx := c.function(fName)
	c.module.Start.FuncIndex = &idx
	return c.storeFunc(fName, c.code)
}

// replaceBooleanFunc finds the `opa_boolean` code section, and replaces it with
// a simpler function, that's returning one of the interned `opa_boolean_t`s
// instead.
// NOTE(sr): We're doing it in this crude way because LLVM 11 doesn't let us
// differentiate that some unknown symbols (opa_abort, opa_builtin0, etc) should
// be created as imports, and other should be ignored. So, we're having a stub
// implementation in wasm/src/value.c that'll get replaced here.
func (c *Compiler) replaceBooleanFunc() error {
	c.code = &module.CodeEntry{}
	c.appendInstr(instruction.I32Const{Value: int32(c.opaBoolAddrs[true])})
	c.appendInstr(instruction.I32Const{Value: int32(c.opaBoolAddrs[false])})
	c.appendInstr(instruction.GetLocal{Index: 0})
	c.appendInstr(instruction.Select{})

	return c.storeFunc(opaBoolean, c.code)
}

func (c *Compiler) compileBlock(block *ir.Block) ([]instruction.Instruction, error) {

	var instrs []instruction.Instruction

	for _, stmt := range block.Stmts {
		switch stmt := stmt.(type) {
		case *ir.ResultSetAddStmt:
			instrs = append(instrs, instruction.GetLocal{Index: c.lrs})
			instrs = append(instrs, instruction.GetLocal{Index: c.local(stmt.Value)})
			instrs = append(instrs, instruction.Call{Index: c.function(opaSetAdd)})
		case *ir.ReturnLocalStmt:
			instrs = append(instrs, instruction.GetLocal{Index: c.local(stmt.Source)})
			instrs = append(instrs, instruction.Return{})
		case *ir.BlockStmt:
			for i := range stmt.Blocks {
				block, err := c.compileBlock(stmt.Blocks[i])
				if err != nil {
					return nil, err
				}
				if withControlInstr(block) {
					instrs = append(instrs, instruction.Block{Instrs: block})
				} else {
					instrs = append(instrs, block...)
				}
			}
		case *ir.BreakStmt:
			instrs = append(instrs, instruction.Br{Index: stmt.Index})
		case *ir.CallStmt:
			if err := c.compileCallStmt(stmt, &instrs); err != nil {
				return nil, err
			}
		case *ir.CallDynamicStmt:
			if err := c.compileCallDynamicStmt(stmt, &instrs); err != nil {
				return nil, err
			}
		case *ir.WithStmt:
			if err := c.compileWithStmt(stmt, &instrs); err != nil {
				return instrs, err
			}
		case *ir.AssignVarStmt:
			instrs = append(instrs, c.instrRead(stmt.Source))
			instrs = append(instrs, instruction.SetLocal{Index: c.local(stmt.Target)})
		case *ir.AssignVarOnceStmt:
			instrs = append(instrs, instruction.Block{
				Instrs: []instruction.Instruction{
					instruction.Block{
						Instrs: append([]instruction.Instruction{
							instruction.GetLocal{Index: c.local(stmt.Target)},
							instruction.I32Eqz{},
							instruction.BrIf{Index: 0},
							instruction.GetLocal{Index: c.local(stmt.Target)},
							c.instrRead(stmt.Source),
							instruction.Call{Index: c.function(opaValueCompare)},
							instruction.I32Eqz{},
							instruction.BrIf{Index: 1},
						},
							c.runtimeErrorAbort(stmt.Location, errVarAssignConflict)...),
					},
					c.instrRead(stmt.Source),
					instruction.SetLocal{Index: c.local(stmt.Target)},
				},
			})
		case *ir.AssignIntStmt:
			instrs = append(instrs, instruction.GetLocal{Index: c.local(stmt.Target)})
			instrs = append(instrs, instruction.I64Const{Value: stmt.Value})
			instrs = append(instrs, instruction.Call{Index: c.function(opaValueNumberSetInt)})
		case *ir.ScanStmt:
			if err := c.compileScan(stmt, &instrs); err != nil {
				return nil, err
			}
		case *ir.NopStmt:
			instrs = append(instrs, instruction.Nop{})
		case *ir.NotStmt:
			if err := c.compileNot(stmt, &instrs); err != nil {
				return nil, err
			}
		case *ir.DotStmt:
			if loc, ok := stmt.Source.Value.(ir.Local); ok {
				instrs = append(instrs, instruction.GetLocal{Index: c.local(loc)})
				instrs = append(instrs, c.instrRead(stmt.Key))
				instrs = append(instrs, instruction.Call{Index: c.function(opaValueGet)})
				instrs = append(instrs, instruction.TeeLocal{Index: c.local(stmt.Target)})
				instrs = append(instrs, instruction.I32Eqz{})
				instrs = append(instrs, instruction.BrIf{Index: 0})
			} else {
				// Booleans and string sources would lead to the BrIf (since opa_value_get
				// on them returns 0), so let's skip trying that.
				instrs = append(instrs, instruction.Br{Index: 0})
				break
			}
		case *ir.LenStmt:
			instrs = append(instrs, c.instrRead(stmt.Source))
			instrs = append(instrs, instruction.Call{Index: c.function(opaValueLength)})
			instrs = append(instrs, instruction.Call{Index: c.function(opaNumberSize)})
			instrs = append(instrs, instruction.SetLocal{Index: c.local(stmt.Target)})
		case *ir.EqualStmt:
			if stmt.A != stmt.B { // constants, or locals, being equal here can skip the check
				instrs = append(instrs, c.instrRead(stmt.A))
				instrs = append(instrs, c.instrRead(stmt.B))
				instrs = append(instrs, instruction.Call{Index: c.function(opaValueCompare)})
				instrs = append(instrs, instruction.BrIf{Index: 0})
			}
		case *ir.NotEqualStmt:
			if stmt.A == stmt.B { // same local, same bool constant, or same string constant
				instrs = append(instrs, instruction.Br{Index: 0})
				continue
			}
			_, okA := stmt.A.Value.(ir.Bool)
			if _, okB := stmt.B.Value.(ir.Bool); okA && okB {
				// not equal (checked above), but both booleans => not equal
				continue
			}
			_, okA = stmt.A.Value.(ir.StringIndex)
			if _, okB := stmt.B.Value.(ir.StringIndex); okA && okB {
				// not equal (checked above), but both strings => not equal
				continue
			}
			instrs = append(instrs, c.instrRead(stmt.A))
			instrs = append(instrs, c.instrRead(stmt.B))
			instrs = append(instrs, instruction.Call{Index: c.function(opaValueCompare)})
			instrs = append(instrs, instruction.I32Eqz{})
			instrs = append(instrs, instruction.BrIf{Index: 0})
		case *ir.MakeNullStmt:
			instrs = append(instrs, instruction.Call{Index: c.function(opaNull)})
			instrs = append(instrs, instruction.SetLocal{Index: c.local(stmt.Target)})
		case *ir.MakeNumberIntStmt:
			instrs = append(instrs, instruction.I64Const{Value: stmt.Value})
			instrs = append(instrs, instruction.Call{Index: c.function(opaNumberInt)})
			instrs = append(instrs, instruction.SetLocal{Index: c.local(stmt.Target)})
		case *ir.MakeNumberRefStmt:
			instrs = append(instrs, instruction.I32Const{Value: c.stringAddr(stmt.Index)})
			instrs = append(instrs, instruction.I32Const{Value: int32(len(c.policy.Static.Strings[stmt.Index].Value))})
			instrs = append(instrs, instruction.Call{Index: c.function(opaNumberRef)})
			instrs = append(instrs, instruction.SetLocal{Index: c.local(stmt.Target)})
		case *ir.MakeArrayStmt:
			instrs = append(instrs, instruction.I32Const{Value: stmt.Capacity})
			instrs = append(instrs, instruction.Call{Index: c.function(opaArrayWithCap)})
			instrs = append(instrs, instruction.SetLocal{Index: c.local(stmt.Target)})
		case *ir.MakeObjectStmt:
			instrs = append(instrs, instruction.Call{Index: c.function(opaObject)})
			instrs = append(instrs, instruction.SetLocal{Index: c.local(stmt.Target)})
		case *ir.MakeSetStmt:
			instrs = append(instrs, instruction.Call{Index: c.function(opaSet)})
			instrs = append(instrs, instruction.SetLocal{Index: c.local(stmt.Target)})
		case *ir.IsArrayStmt:
			if loc, ok := stmt.Source.Value.(ir.Local); ok {
				instrs = append(instrs, instruction.GetLocal{Index: c.local(loc)})
				instrs = append(instrs, instruction.Call{Index: c.function(opaValueType)})
				instrs = append(instrs, instruction.I32Const{Value: opaTypeArray})
				instrs = append(instrs, instruction.I32Ne{})
				instrs = append(instrs, instruction.BrIf{Index: 0})
			} else {
				instrs = append(instrs, instruction.Br{Index: 0})
				break
			}
		case *ir.IsObjectStmt:
			if loc, ok := stmt.Source.Value.(ir.Local); ok {
				instrs = append(instrs, instruction.GetLocal{Index: c.local(loc)})
				instrs = append(instrs, instruction.Call{Index: c.function(opaValueType)})
				instrs = append(instrs, instruction.I32Const{Value: opaTypeObject})
				instrs = append(instrs, instruction.I32Ne{})
				instrs = append(instrs, instruction.BrIf{Index: 0})
			} else {
				instrs = append(instrs, instruction.Br{Index: 0})
				break
			}
		case *ir.IsUndefinedStmt:
			instrs = append(instrs, instruction.GetLocal{Index: c.local(stmt.Source)})
			instrs = append(instrs, instruction.I32Const{Value: 0})
			instrs = append(instrs, instruction.I32Ne{})
			instrs = append(instrs, instruction.BrIf{Index: 0})
		case *ir.ResetLocalStmt:
			instrs = append(instrs, instruction.I32Const{Value: 0})
			instrs = append(instrs, instruction.SetLocal{Index: c.local(stmt.Target)})
		case *ir.IsDefinedStmt:
			instrs = append(instrs, instruction.GetLocal{Index: c.local(stmt.Source)})
			instrs = append(instrs, instruction.I32Eqz{})
			instrs = append(instrs, instruction.BrIf{Index: 0})
		case *ir.ArrayAppendStmt:
			instrs = append(instrs, instruction.GetLocal{Index: c.local(stmt.Array)})
			instrs = append(instrs, c.instrRead(stmt.Value))
			instrs = append(instrs, instruction.Call{Index: c.function(opaArrayAppend)})
		case *ir.ObjectInsertStmt:
			instrs = append(instrs, instruction.GetLocal{Index: c.local(stmt.Object)})
			instrs = append(instrs, c.instrRead(stmt.Key))
			instrs = append(instrs, c.instrRead(stmt.Value))
			instrs = append(instrs, instruction.Call{Index: c.function(opaObjectInsert)})
		case *ir.ObjectInsertOnceStmt:
			tmp := c.genLocal()
			instrs = append(instrs, instruction.Block{
				Instrs: []instruction.Instruction{
					instruction.Block{
						Instrs: append([]instruction.Instruction{
							instruction.GetLocal{Index: c.local(stmt.Object)},
							c.instrRead(stmt.Key),
							instruction.Call{Index: c.function(opaValueGet)},
							instruction.TeeLocal{Index: tmp},
							instruction.I32Eqz{},
							instruction.BrIf{Index: 0},
							instruction.GetLocal{Index: tmp},
							c.instrRead(stmt.Value),
							instruction.Call{Index: c.function(opaValueCompare)},
							instruction.I32Eqz{},
							instruction.BrIf{Index: 1},
						}, c.runtimeErrorAbort(stmt.Location, errObjectInsertConflict)...),
					},
					instruction.GetLocal{Index: c.local(stmt.Object)},
					c.instrRead(stmt.Key),
					c.instrRead(stmt.Value),
					instruction.Call{Index: c.function(opaObjectInsert)},
				},
			})
		case *ir.ObjectMergeStmt:
			instrs = append(instrs, instruction.GetLocal{Index: c.local(stmt.A)})
			instrs = append(instrs, instruction.GetLocal{Index: c.local(stmt.B)})
			instrs = append(instrs, instruction.Call{Index: c.function(opaValueMerge)})
			instrs = append(instrs, instruction.SetLocal{Index: c.local(stmt.Target)})
		case *ir.SetAddStmt:
			instrs = append(instrs, instruction.GetLocal{Index: c.local(stmt.Set)})
			instrs = append(instrs, c.instrRead(stmt.Value))
			instrs = append(instrs, instruction.Call{Index: c.function(opaSetAdd)})
		default:
			var buf bytes.Buffer
			err := ir.Pretty(&buf, stmt)
			if err != nil {
				return nil, err
			}
			return instrs, fmt.Errorf("illegal statement: %v", buf.String())
		}
	}

	return instrs, nil
}

func (c *Compiler) compileScan(scan *ir.ScanStmt, result *[]instruction.Instruction) error {
	var instrs = *result
	instrs = append(instrs, instruction.I32Const{Value: 0})
	instrs = append(instrs, instruction.SetLocal{Index: c.local(scan.Key)})
	body, err := c.compileScanBlock(scan)
	if err != nil {
		return err
	}
	instrs = append(instrs, instruction.Block{
		Instrs: []instruction.Instruction{
			instruction.Loop{Instrs: body},
		},
	})
	*result = instrs
	return nil
}

func (c *Compiler) compileScanBlock(scan *ir.ScanStmt) ([]instruction.Instruction, error) {
	var instrs []instruction.Instruction

	// Execute iterator.
	instrs = append(instrs, instruction.GetLocal{Index: c.local(scan.Source)})
	instrs = append(instrs, instruction.GetLocal{Index: c.local(scan.Key)})
	instrs = append(instrs, instruction.Call{Index: c.function(opaValueIter)})

	// Check for emptiness.
	instrs = append(instrs, instruction.TeeLocal{Index: c.local(scan.Key)})
	instrs = append(instrs, instruction.I32Eqz{})
	instrs = append(instrs, instruction.BrIf{Index: 1})

	// Load value.
	instrs = append(instrs, instruction.GetLocal{Index: c.local(scan.Source)})
	instrs = append(instrs, instruction.GetLocal{Index: c.local(scan.Key)})
	instrs = append(instrs, instruction.Call{Index: c.function(opaValueGet)})
	instrs = append(instrs, instruction.SetLocal{Index: c.local(scan.Value)})

	// Loop body.
	nested, err := c.compileBlock(scan.Block)
	if err != nil {
		return nil, err
	}

	// Continue.
	instrs = append(instrs, nested...)
	instrs = append(instrs, instruction.Br{Index: 0})

	return instrs, nil
}

func (c *Compiler) compileNot(not *ir.NotStmt, result *[]instruction.Instruction) error {
	var instrs = *result

	// generate and initialize condition variable
	cond := c.genLocal()
	instrs = append(instrs, instruction.I32Const{Value: 1})
	instrs = append(instrs, instruction.SetLocal{Index: cond})

	nested, err := c.compileBlock(not.Block)
	if err != nil {
		return err
	}

	// unset condition variable if end of block is reached
	nested = append(nested, instruction.I32Const{Value: 0})
	nested = append(nested, instruction.SetLocal{Index: cond})
	instrs = append(instrs, instruction.Block{Instrs: nested})

	// break out of block if condition variable was unset
	instrs = append(instrs, instruction.GetLocal{Index: cond})
	instrs = append(instrs, instruction.I32Eqz{})
	instrs = append(instrs, instruction.BrIf{Index: 0})

	*result = instrs
	return nil
}

func (c *Compiler) compileWithStmt(with *ir.WithStmt, result *[]instruction.Instruction) error {

	var instrs = *result
	save := c.genLocal()
	instrs = append(instrs, instruction.Call{Index: c.function(opaMemoizePush)})
	instrs = append(instrs, instruction.GetLocal{Index: c.local(with.Local)})
	instrs = append(instrs, instruction.SetLocal{Index: save})

	if len(with.Path) == 0 {
		instrs = append(instrs, c.instrRead(with.Value))
		instrs = append(instrs, instruction.SetLocal{Index: c.local(with.Local)})
	} else {
		instrs = c.compileUpsert(with.Local, with.Path, with.Value, with.Location, instrs)
	}

	undefined := c.genLocal()
	instrs = append(instrs, instruction.I32Const{Value: 1})
	instrs = append(instrs, instruction.SetLocal{Index: undefined})

	nested, err := c.compileBlock(with.Block)
	if err != nil {
		return err
	}

	nested = append(nested, instruction.I32Const{Value: 0})
	nested = append(nested, instruction.SetLocal{Index: undefined})
	instrs = append(instrs, instruction.Block{Instrs: nested})
	instrs = append(instrs, instruction.GetLocal{Index: save})
	instrs = append(instrs, instruction.SetLocal{Index: c.local(with.Local)})
	instrs = append(instrs, instruction.Call{Index: c.function(opaMemoizePop)})
	instrs = append(instrs, instruction.GetLocal{Index: undefined})
	instrs = append(instrs, instruction.BrIf{Index: 0})

	*result = instrs

	return nil
}

func (c *Compiler) compileUpsert(local ir.Local, path []int, value ir.Operand, loc ir.Location, instrs []instruction.Instruction) []instruction.Instruction {

	lcopy := c.genLocal() // holds copy of local
	instrs = append(instrs, instruction.GetLocal{Index: c.local(local)})
	instrs = append(instrs, instruction.SetLocal{Index: lcopy})

	// Shallow copy the local if defined otherwise initialize to an empty object.
	instrs = append(instrs, instruction.Block{
		Instrs: []instruction.Instruction{
			instruction.Block{Instrs: []instruction.Instruction{
				instruction.GetLocal{Index: lcopy},
				instruction.I32Eqz{},
				instruction.BrIf{Index: 0},
				instruction.GetLocal{Index: lcopy},
				instruction.Call{Index: c.function(opaValueShallowCopy)},
				instruction.TeeLocal{Index: lcopy},
				instruction.SetLocal{Index: c.local(local)},
				instruction.Br{Index: 1},
			}},
			instruction.Call{Index: c.function(opaObject)},
			instruction.TeeLocal{Index: lcopy},
			instruction.SetLocal{Index: c.local(local)},
		},
	})

	// Initialize the locals that specify the path of the upsert operation.
	lpath := make(map[int]uint32, len(path))

	for i := 0; i < len(path); i++ {
		lpath[i] = c.genLocal()
		instrs = append(instrs, instruction.I32Const{Value: c.opaStringAddr(path[i])})
		instrs = append(instrs, instruction.SetLocal{Index: lpath[i]})
	}

	// Generate a block that traverses the path of the upsert operation,
	// shallowing copying values at each step as needed. Stop before the final
	// segment that will only be inserted.
	var inner []instruction.Instruction
	ltemp := c.genLocal()

	for i := 0; i < len(path)-1; i++ {

		// Lookup the next part of the path.
		inner = append(inner, instruction.GetLocal{Index: lcopy})
		inner = append(inner, instruction.GetLocal{Index: lpath[i]})
		inner = append(inner, instruction.Call{Index: c.function(opaValueGet)})
		inner = append(inner, instruction.SetLocal{Index: ltemp})

		// If the next node is missing, break.
		inner = append(inner, instruction.GetLocal{Index: ltemp})
		inner = append(inner, instruction.I32Eqz{})
		inner = append(inner, instruction.BrIf{Index: uint32(i)})

		// If the next node is not an object, break.
		inner = append(inner, instruction.GetLocal{Index: ltemp})
		inner = append(inner, instruction.Call{Index: c.function(opaValueType)})
		inner = append(inner, instruction.I32Const{Value: opaTypeObject})
		inner = append(inner, instruction.I32Ne{})
		inner = append(inner, instruction.BrIf{Index: uint32(i)})

		// Otherwise, shallow copy the next node node and insert into the copy
		// before continuing.
		inner = append(inner, instruction.GetLocal{Index: ltemp})
		inner = append(inner, instruction.Call{Index: c.function(opaValueShallowCopy)})
		inner = append(inner, instruction.SetLocal{Index: ltemp})
		inner = append(inner, instruction.GetLocal{Index: lcopy})
		inner = append(inner, instruction.GetLocal{Index: lpath[i]})
		inner = append(inner, instruction.GetLocal{Index: ltemp})
		inner = append(inner, instruction.Call{Index: c.function(opaObjectInsert)})
		inner = append(inner, instruction.GetLocal{Index: ltemp})
		inner = append(inner, instruction.SetLocal{Index: lcopy})
	}

	inner = append(inner, instruction.Br{Index: uint32(len(path) - 1)})

	// Generate blocks that handle missing nodes during traversal.
	var block []instruction.Instruction
	lval := c.genLocal()

	for i := 0; i < len(path)-1; i++ {
		block = append(block, instruction.Block{Instrs: inner})
		block = append(block, instruction.Call{Index: c.function(opaObject)})
		block = append(block, instruction.SetLocal{Index: lval})
		block = append(block, instruction.GetLocal{Index: lcopy})
		block = append(block, instruction.GetLocal{Index: lpath[i]})
		block = append(block, instruction.GetLocal{Index: lval})
		block = append(block, instruction.Call{Index: c.function(opaObjectInsert)})
		block = append(block, instruction.GetLocal{Index: lval})
		block = append(block, instruction.SetLocal{Index: lcopy})
		inner = block
		block = nil
	}

	// Finish by inserting the statement's value into the shallow copied node.
	instrs = append(instrs, instruction.Block{Instrs: inner})
	instrs = append(instrs, instruction.GetLocal{Index: lcopy})
	instrs = append(instrs, instruction.GetLocal{Index: lpath[len(path)-1]})
	instrs = append(instrs, c.instrRead(value))
	instrs = append(instrs, instruction.Call{Index: c.function(opaObjectInsert)})

	return instrs
}

func (c *Compiler) compileCallDynamicStmt(stmt *ir.CallDynamicStmt, result *[]instruction.Instruction) error {
	instrs := []instruction.Instruction{}
	larray := c.genLocal()
	lidx := c.genLocal()

	// init array:
	instrs = append(instrs,
		instruction.I32Const{Value: int32(len(stmt.Path))},
		instruction.Call{Index: c.function(opaArrayWithCap)},
		instruction.SetLocal{Index: larray},
	)

	// append to it:
	for _, lv := range stmt.Path {
		instrs = append(instrs,
			instruction.GetLocal{Index: larray},
			c.instrRead(lv),
			instruction.Call{Index: c.function(opaArrayAppend)},
		)
	}

	// prep stack for later call_indirect
	for _, arg := range stmt.Args {
		instrs = append(instrs, instruction.GetLocal{Index: c.local(arg)})
	}

	tpe := module.FunctionType{
		Params:  []types.ValueType{types.I32, types.I32}, // data, input
		Results: []types.ValueType{types.I32},
	}
	typeIndex := c.emitFunctionType(tpe)

	instrs = append(instrs,
		// lookup elem idx via larray path
		instruction.GetLocal{Index: larray},
		instruction.Call{Index: c.function(opaMappingLookup)}, // [arg0 arg1 larray] -> [arg0 arg1 tbl_idx]
		instruction.TeeLocal{Index: lidx},
		instruction.I32Eqz{},       // mapping not found
		instruction.BrIf{Index: 0}, // check data

		instruction.GetLocal{Index: lidx},
		instruction.CallIndirect{Index: typeIndex}, // [arg0 arg1 tbl_idx] -> [res]
		instruction.TeeLocal{Index: c.local(stmt.Result)},
		instruction.I32Eqz{},
		instruction.BrIf{Index: 3}, // mapping found, "undefined" result counts
	)

	*result = append(*result, instrs...)
	return nil
}

func (c *Compiler) compileCallStmt(stmt *ir.CallStmt, result *[]instruction.Instruction) error {

	fn := stmt.Func

	if name, ok := builtinsFunctions[stmt.Func]; ok {
		fn = name
	}

	if index, ok := c.funcs[fn]; ok {
		return c.compileInternalCall(stmt, index, result)
	}

	if ef, ok := c.externalFuncs[fn]; ok {
		return c.compileExternalCall(stmt, ef, result)
	}

	c.errors = append(c.errors, fmt.Errorf("undefined function: %q", fn))

	return nil
}

func (c *Compiler) compileInternalCall(stmt *ir.CallStmt, index uint32, result *[]instruction.Instruction) error {

	instrs := []instruction.Instruction{}

	// Prepare function args and call.
	for _, arg := range stmt.Args {
		instrs = append(instrs, c.instrRead(arg))
	}

	instrs = append(instrs,
		instruction.Call{Index: index},
		instruction.TeeLocal{Index: c.local(stmt.Result)},
		instruction.I32Eqz{},
		instruction.BrIf{Index: 0})

	*result = append(*result, instrs...)

	return nil
}

func (c *Compiler) compileExternalCall(stmt *ir.CallStmt, ef externalFunc, result *[]instruction.Instruction) error {

	if len(stmt.Args) >= len(builtinDispatchers) {
		c.errors = append(c.errors, fmt.Errorf("too many built-in call arguments: %q", stmt.Func))
		return nil
	}

	instrs := *result
	instrs = append(instrs, instruction.I32Const{Value: ef.ID})
	instrs = append(instrs, instruction.I32Const{Value: 0}) // unused context parameter

	for _, arg := range stmt.Args {
		instrs = append(instrs, c.instrRead(arg))
	}

	instrs = append(instrs, instruction.Call{Index: c.function(builtinDispatchers[len(stmt.Args)])})

	if ef.Decl.Result() != nil {
		instrs = append(instrs, instruction.TeeLocal{Index: c.local(stmt.Result)})
		instrs = append(instrs, instruction.I32Eqz{})
		instrs = append(instrs, instruction.BrIf{Index: 0})
	} else {
		instrs = append(instrs, instruction.Drop{})
	}

	*result = instrs
	return nil
}

func (c *Compiler) emitFunctionDecl(name string, tpe module.FunctionType, export bool) {

	var idx uint32
	if old, ok := c.funcs[name]; ok {
		c.debug.Printf("function declaration for %v is being emitted multiple times (overwriting old index %d)", name, old)
		idx = old
	} else {
		typeIndex := c.emitFunctionType(tpe)
		c.module.Function.TypeIndices = append(c.module.Function.TypeIndices, typeIndex)
		c.module.Code.Segments = append(c.module.Code.Segments, module.RawCodeSegment{})
		idx = uint32((len(c.module.Function.TypeIndices) - 1) + c.functionImportCount())
		c.funcs[name] = idx
	}

	if export {
		c.module.Export.Exports = append(c.module.Export.Exports, module.Export{
			Name: name,
			Descriptor: module.ExportDescriptor{
				Type:  module.FunctionExportType,
				Index: idx,
			},
		})
	}

	// add functions 'name' entry
	var found bool
	for _, m := range c.module.Names.Functions {
		if m.Index == idx {
			found = true
		}
	}
	if !found {
		c.module.Names.Functions = append(c.module.Names.Functions, module.NameMap{
			Index: idx,
			Name:  name,
		})
	}
}

func (c *Compiler) emitFunctionType(tpe module.FunctionType) uint32 {
	for i, other := range c.module.Type.Functions {
		if tpe.Equal(other) {
			return uint32(i)
		}
	}
	c.module.Type.Functions = append(c.module.Type.Functions, tpe)
	return uint32(len(c.module.Type.Functions) - 1)
}

func (c *Compiler) emitFunction(name string, entry *module.CodeEntry) error {
	var buf bytes.Buffer
	if err := encoding.WriteCodeEntry(&buf, entry); err != nil {
		return err
	}
	index := c.function(name) - uint32(c.functionImportCount())
	c.module.Code.Segments[index].Code = buf.Bytes()
	return nil
}

// emitFuncs writes the compiled (and optimized) functions' code into the
// module
func (c *Compiler) emitFuncs() error {
	for _, fn := range c.funcsCode {
		if err := c.emitFunction(fn.name, fn.code); err != nil {
			return fmt.Errorf("write function %s: %w", fn.name, err)
		}
	}
	return nil
}

func (c *Compiler) functionImportCount() int {
	var count int

	for _, imp := range c.module.Import.Imports {
		if imp.Descriptor.Kind() == module.FunctionImportType {
			count++
		}
	}

	return count
}

func (c *Compiler) stringAddr(index int) int32 {
	return int32(c.stringAddrs[index])
}

func (c *Compiler) builtinStringAddr(code int) int32 {
	return int32(c.builtinStringAddrs[code])
}

func (c *Compiler) opaStringAddr(index int) int32 {
	return int32(c.opaStringAddrs[index])
}

func (c *Compiler) opaBoolAddr(b ir.Bool) int32 {
	return int32(c.opaBoolAddrs[b])
}

func (c *Compiler) fileAddr(code int) int32 {
	return int32(c.fileAddrs[code])
}

func (c *Compiler) local(l ir.Local) uint32 {
	var u32 uint32
	var exist bool
	if u32, exist = c.locals[l]; !exist {
		u32 = c.nextLocal
		c.locals[l] = u32
		c.nextLocal++
	}
	return u32
}

func (c *Compiler) genLocal() uint32 {
	l := c.nextLocal
	c.nextLocal++
	return l
}

func (c *Compiler) function(name string) uint32 {
	fidx, ok := c.funcs[name]
	if !ok {
		panic(fmt.Sprintf("function not found: %s", name))
	}
	return fidx
}

func (c *Compiler) appendInstr(instr instruction.Instruction) {
	c.code.Func.Expr.Instrs = append(c.code.Func.Expr.Instrs, instr)
}

func (c *Compiler) appendInstrs(instrs []instruction.Instruction) {
	for _, instr := range instrs {
		c.appendInstr(instr)
	}
}

func getLowestFreeDataSegmentOffset(m *module.Module) (int32, error) {

	var offset int32

	for i := range m.Data.Segments {

		if len(m.Data.Segments[i].Offset.Instrs) != 1 {
			return 0, errors.New("bad data segment offset instructions")
		}

		instr, ok := m.Data.Segments[i].Offset.Instrs[0].(instruction.I32Const)
		if !ok {
			return 0, errors.New("bad data segment offset expr")
		}

		// NOTE(tsandall): assume memory up to but not including addr is taken.
		addr := instr.Value + int32(len(m.Data.Segments[i].Init))
		if addr > offset {
			offset = addr
		}
	}

	return offset, nil
}

func getLowestFreeElementSegmentOffset(m *module.Module) (int32, error) {
	var offset int32

	for _, seg := range m.Element.Segments {
		if len(seg.Offset.Instrs) != 1 {
			return 0, errors.New("bad data segment offset instructions")
		}

		instr, ok := seg.Offset.Instrs[0].(instruction.I32Const)
		if !ok {
			return 0, errors.New("bad data segment offset expr")
		}

		addr := instr.Value + int32(len(seg.Indices))
		if addr > offset {
			offset = addr
		}
	}

	return offset, nil
}

// runtimeErrorAbort uses the passed source location to build the
// arguments for a call to opa_runtime_error(file, row, col, msg).
// It returns the instructions that make up the function call with
// arguments, followed by Unreachable.
func (c *Compiler) runtimeErrorAbort(loc ir.Location, errType int) []instruction.Instruction {
	index, row, col := loc.File, loc.Row, loc.Col
	return []instruction.Instruction{
		instruction.I32Const{Value: c.fileAddr(index)},
		instruction.I32Const{Value: int32(row)},
		instruction.I32Const{Value: int32(col)},
		instruction.I32Const{Value: c.builtinStringAddr(errType)},
		instruction.Call{Index: c.function(opaRuntimeError)},
		instruction.Unreachable{},
	}
}

func (c *Compiler) storeFunc(name string, code *module.CodeEntry) error {
	for _, fn := range c.funcsCode {
		if fn.name == name {
			return fmt.Errorf("duplicate function entry %s", name)
		}
	}
	c.funcsCode = append(c.funcsCode, funcCode{name: name, code: code})
	return nil
}

func (c *Compiler) instrRead(lv ir.Operand) instruction.Instruction {
	switch x := lv.Value.(type) {
	case ir.Bool:
		return instruction.I32Const{Value: c.opaBoolAddr(x)}
	case ir.StringIndex:
		return instruction.I32Const{Value: c.opaStringAddr(int(x))}
	case ir.Local:
		return instruction.GetLocal{Index: c.local(x)}
	}
	panic("unreachable")
}
