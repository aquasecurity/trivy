// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ast

// CompileModules takes a set of Rego modules represented as strings and
// compiles them for evaluation. The keys of the map are used as filenames.
func CompileModules(modules map[string]string) (*Compiler, error) {
	return CompileModulesWithOpt(modules, CompileOpts{})
}

// CompileOpts defines a set of options for the compiler.
type CompileOpts struct {
	EnablePrintStatements bool
	ParserOptions         ParserOptions
}

// CompileModulesWithOpt takes a set of Rego modules represented as strings and
// compiles them for evaluation. The keys of the map are used as filenames.
func CompileModulesWithOpt(modules map[string]string, opts CompileOpts) (*Compiler, error) {

	parsed := make(map[string]*Module, len(modules))

	for f, module := range modules {
		var pm *Module
		var err error
		if pm, err = ParseModuleWithOpts(f, module, opts.ParserOptions); err != nil {
			return nil, err
		}
		parsed[f] = pm
	}

	compiler := NewCompiler().WithEnablePrintStatements(opts.EnablePrintStatements)
	compiler.Compile(parsed)

	if compiler.Failed() {
		return nil, compiler.Errors
	}

	return compiler, nil
}

// MustCompileModules compiles a set of Rego modules represented as strings. If
// the compilation process fails, this function panics.
func MustCompileModules(modules map[string]string) *Compiler {
	return MustCompileModulesWithOpts(modules, CompileOpts{})
}

// MustCompileModulesWithOpts compiles a set of Rego modules represented as strings. If
// the compilation process fails, this function panics.
func MustCompileModulesWithOpts(modules map[string]string, opts CompileOpts) *Compiler {

	compiler, err := CompileModulesWithOpt(modules, opts)
	if err != nil {
		panic(err)
	}

	return compiler
}
