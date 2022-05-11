package wasm

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/internal/compiler/wasm/opa"
	"github.com/open-policy-agent/opa/internal/wasm/encoding"
	"github.com/open-policy-agent/opa/internal/wasm/instruction"
	"github.com/open-policy-agent/opa/internal/wasm/module"
)

const warning = `---------------------------------------------------------------
WARNING: Using EXPERIMENTAL, unsupported wasm-opt optimization.
         It is not supported, and may go away in the future.
---------------------------------------------------------------`

// optimizeBinaryen passes the encoded module into wasm-opt, and replaces
// the compiler's module with the decoding of the process' output.
func (c *Compiler) optimizeBinaryen() error {
	if os.Getenv("EXPERIMENTAL_WASM_OPT") == "" && os.Getenv("EXPERIMENTAL_WASM_OPT_ARGS") == "" {
		c.debug.Printf("not opted in, skipping wasm-opt optimization")
		return nil
	}
	if !woptFound() {
		c.debug.Printf("wasm-opt binary not found, skipping optimization")
		return nil
	}
	if os.Getenv("EXPERIMENTAL_WASM_OPT") != "silent" { // for benchmarks
		fmt.Fprintln(os.Stderr, warning)
	}
	args := []string{ // WARNING: flags with typos are ignored!
		"-O2",
		"--debuginfo", // don't strip name section
	}
	// allow overriding the options
	if env := os.Getenv("EXPERIMENTAL_WASM_OPT_ARGS"); env != "" {
		args = strings.Split(env, " ")
	}

	args = append(args, "-o", "-") // always output to stdout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	wopt := exec.CommandContext(ctx, "wasm-opt", args...)
	stdin, err := wopt.StdinPipe()
	if err != nil {
		return fmt.Errorf("get stdin: %w", err)
	}
	defer stdin.Close()

	var stdout, stderr bytes.Buffer
	wopt.Stdout = &stdout

	if err := wopt.Start(); err != nil {
		return fmt.Errorf("start wasm-opt: %w", err)
	}
	if err := encoding.WriteModule(stdin, c.module); err != nil {
		return fmt.Errorf("encode module: %w", err)
	}
	if err := stdin.Close(); err != nil {
		return fmt.Errorf("write to wasm-opt: %w", err)
	}
	if err := wopt.Wait(); err != nil {
		return fmt.Errorf("wait for wasm-opt: %w", err)
	}

	if d := stderr.String(); d != "" {
		c.debug.Printf("wasm-opt debug output: %s", d)
	}
	mod, err := encoding.ReadModule(&stdout)
	if err != nil {
		return fmt.Errorf("decode module: %w", err)
	}
	c.module = mod
	return nil
}

func woptFound() bool {
	_, err := exec.LookPath("wasm-opt")
	return err == nil
}

// NOTE(sr): Yes, there are more control instructions than these two,
// but we haven't made use of them yet. So this function only checks
// for the control instructions we're possibly emitting, and which are
// relevant for block nesting.
func withControlInstr(is []instruction.Instruction) bool {
	for _, i := range is {
		switch i := i.(type) {
		case instruction.Br, instruction.BrIf:
			return true
		case instruction.StructuredInstruction:
			// NOTE(sr): We could attempt to further flatten the nested blocks
			// here, but I believe we'd then have to correct block labels.
			if withControlInstr(i.Instructions()) {
				return true
			}
		}
	}
	return false
}

func unquote(s string) (string, error) {
	return strconv.Unquote("\"" + strings.ReplaceAll(s, `\`, `\x`) + "\"")
}

func (c *Compiler) removeUnusedCode() error {
	cgCSV, err := opa.CallGraphCSV()
	if err != nil {
		return fmt.Errorf("csv unpack: %w", err)
	}
	r := csv.NewReader(bytes.NewReader(cgCSV))
	r.LazyQuotes = true
	cg, err := r.ReadAll()
	if err != nil {
		return fmt.Errorf("csv read: %w", err)
	}

	cgIdx := map[uint32][]uint32{}
	for i := range cg {
		callerName, err := unquote(cg[i][0])
		if err != nil {
			return fmt.Errorf("unquote caller name %s: %w", cg[i][0], err)
		}
		calleeName, err := unquote(cg[i][1])
		if err != nil {
			return fmt.Errorf("unquote callee name %s: %w", cg[i][1], err)
		}
		caller, ok := c.funcs[callerName]
		if !ok {
			return fmt.Errorf("caller not found: %s (%s)", cg[i][0], callerName)
		}
		callee, ok := c.funcs[calleeName]
		if !ok {
			return fmt.Errorf("callee not found: %s (%s)", cg[i][1], calleeName)
		}
		cgIdx[caller] = append(cgIdx[caller], callee)
	}

	// add the calls from planned functions
	for _, f := range c.funcsCode {
		fidx := c.funcs[f.name]
		cgIdx[fidx] = findCallees(f.code.Func.Expr.Instrs)
	}

	keepFuncs := map[uint32]struct{}{}

	// we'll keep
	// - what's referenced in a table (these could be called indirectly)
	// - what's exported or imported
	// - what's been compiled by us
	// - anything transitively called from those

	for _, imp := range c.module.Import.Imports {
		if _, ok := imp.Descriptor.(module.FunctionImport); ok {
			reach(cgIdx, keepFuncs, c.funcs[imp.Name])
		}
	}

	for _, exp := range c.module.Export.Exports {
		if exp.Descriptor.Type == module.FunctionExportType {
			reach(cgIdx, keepFuncs, c.funcs[exp.Name])
		}
	}

	for _, f := range c.funcsCode {
		reach(cgIdx, keepFuncs, c.funcs[f.name])
	}

	// anything referenced in a table
	for _, seg := range c.module.Element.Segments {
		for _, idx := range seg.Indices {
			if c.skipElemRE2(keepFuncs, idx) {
				c.debug.Printf("dropping element %d because policy does not depend on re2", idx)
			} else {
				reach(cgIdx, keepFuncs, idx)
			}
		}
	}

	// remove all that's not needed, update index for remaining ones
	funcNames := []module.NameMap{}
	for _, nm := range c.module.Names.Functions {
		if _, ok := keepFuncs[nm.Index]; ok {
			funcNames = append(funcNames, nm)
		}
	}
	c.module.Names.Functions = funcNames

	// For anything that we don't want, replace the function code entries'
	// expressions with `unreachable`.
	// We do this because it lets the resulting wasm module pass `wasm-validate`,
	// empty bodies would not.
	nopEntry := module.Function{
		Expr: module.Expr{
			Instrs: []instruction.Instruction{instruction.Unreachable{}},
		},
	}
	var buf bytes.Buffer
	if err := encoding.WriteCodeEntry(&buf, &module.CodeEntry{Func: nopEntry}); err != nil {
		return fmt.Errorf("write code entry: %w", err)
	}
	for i := range c.module.Code.Segments {
		idx := i + c.functionImportCount()
		if _, ok := keepFuncs[uint32(idx)]; !ok {
			c.module.Code.Segments[i].Code = buf.Bytes()
		}
	}
	return nil
}

func findCallees(instrs []instruction.Instruction) []uint32 {
	var ret []uint32
	for _, expr := range instrs {
		switch expr := expr.(type) {
		case instruction.Call:
			ret = append(ret, expr.Index)
		case instruction.StructuredInstruction:
			ret = append(ret, findCallees(expr.Instructions())...)
		}
	}
	return ret
}

func reach(cg map[uint32][]uint32, keep map[uint32]struct{}, node uint32) {
	if _, ok := keep[node]; !ok {
		keep[node] = struct{}{}
		for _, v := range cg[node] {
			reach(cg, keep, v)
		}
	}
}

// skipElemRE2 determines if a function in the table is really required:
// We'll exclude anything with a prefix of "re2::" if none of the known
// entrypoints into re2 are used.
func (c *Compiler) skipElemRE2(keep map[uint32]struct{}, idx uint32) bool {
	if c.usesRE2(keep) {
		return false
	}
	return c.nameContains(idx, "re2::", "lexer::", "std::", "__cxa_pure_virtual", "operator", "parser_")
}

func (c *Compiler) usesRE2(keep map[uint32]struct{}) bool {
	for _, fn := range builtinsUsingRE2 {
		if _, ok := keep[c.function(fn)]; ok {
			return true
		}
	}
	return false
}

func (c *Compiler) nameContains(idx uint32, hs ...string) bool {
	// TODO(sr): keep reverse mapping (idx -> name) in Compiler struct
	for _, nm := range c.module.Names.Functions {
		if nm.Index == idx {
			for _, h := range hs {
				if strings.Contains(nm.Name, h) {
					return true
				}
			}
			return false
		}
	}
	return false
}
