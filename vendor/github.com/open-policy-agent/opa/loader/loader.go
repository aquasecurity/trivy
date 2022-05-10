// Copyright 2017 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package loader contains utilities for loading files into OPA.
package loader

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ghodss/yaml"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	fileurl "github.com/open-policy-agent/opa/internal/file/url"
	"github.com/open-policy-agent/opa/internal/merge"
	"github.com/open-policy-agent/opa/metrics"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
)

// Result represents the result of successfully loading zero or more files.
type Result struct {
	Documents map[string]interface{}
	Modules   map[string]*RegoFile
	path      []string
}

// ParsedModules returns the parsed modules stored on the result.
func (l *Result) ParsedModules() map[string]*ast.Module {
	modules := make(map[string]*ast.Module)
	for _, module := range l.Modules {
		modules[module.Name] = module.Parsed
	}
	return modules
}

// Compiler returns a Compiler object with the compiled modules from this loader
// result.
func (l *Result) Compiler() (*ast.Compiler, error) {
	compiler := ast.NewCompiler()
	compiler.Compile(l.ParsedModules())
	if compiler.Failed() {
		return nil, compiler.Errors
	}
	return compiler, nil
}

// Store returns a Store object with the documents from this loader result.
func (l *Result) Store() (storage.Store, error) {
	return inmem.NewFromObject(l.Documents), nil
}

// RegoFile represents the result of loading a single Rego source file.
type RegoFile struct {
	Name   string
	Parsed *ast.Module
	Raw    []byte
}

// Filter defines the interface for filtering files during loading. If the
// filter returns true, the file should be excluded from the result.
type Filter func(abspath string, info os.FileInfo, depth int) bool

// GlobExcludeName excludes files and directories whose names do not match the
// shell style pattern at minDepth or greater.
func GlobExcludeName(pattern string, minDepth int) Filter {
	return func(abspath string, info os.FileInfo, depth int) bool {
		match, _ := filepath.Match(pattern, info.Name())
		return match && depth >= minDepth
	}
}

// FileLoader defines an interface for loading OPA data files
// and Rego policies.
type FileLoader interface {
	All(paths []string) (*Result, error)
	Filtered(paths []string, filter Filter) (*Result, error)
	AsBundle(path string) (*bundle.Bundle, error)
	WithMetrics(m metrics.Metrics) FileLoader
	WithBundleVerificationConfig(*bundle.VerificationConfig) FileLoader
	WithSkipBundleVerification(skipVerify bool) FileLoader
	WithProcessAnnotation(processAnnotation bool) FileLoader
}

// NewFileLoader returns a new FileLoader instance.
func NewFileLoader() FileLoader {
	return &fileLoader{
		metrics: metrics.New(),
		files:   make(map[string]bundle.FileInfo),
	}
}

type fileLoader struct {
	metrics    metrics.Metrics
	bvc        *bundle.VerificationConfig
	skipVerify bool
	files      map[string]bundle.FileInfo
	opts       ast.ParserOptions
}

// WithMetrics provides the metrics instance to use while loading
func (fl *fileLoader) WithMetrics(m metrics.Metrics) FileLoader {
	fl.metrics = m
	return fl
}

// WithBundleVerificationConfig sets the key configuration used to verify a signed bundle
func (fl *fileLoader) WithBundleVerificationConfig(config *bundle.VerificationConfig) FileLoader {
	fl.bvc = config
	return fl
}

// WithSkipBundleVerification skips verification of a signed bundle
func (fl *fileLoader) WithSkipBundleVerification(skipVerify bool) FileLoader {
	fl.skipVerify = skipVerify
	return fl
}

// WithProcessAnnotation enables or disables processing of schema annotations on rules
func (fl *fileLoader) WithProcessAnnotation(processAnnotation bool) FileLoader {
	fl.opts.ProcessAnnotation = processAnnotation
	return fl
}

// All returns a Result object loaded (recursively) from the specified paths.
func (fl fileLoader) All(paths []string) (*Result, error) {
	return fl.Filtered(paths, nil)
}

// Filtered returns a Result object loaded (recursively) from the specified
// paths while applying the given filters. If any filter returns true, the
// file/directory is excluded.
func (fl fileLoader) Filtered(paths []string, filter Filter) (*Result, error) {
	return all(paths, filter, func(curr *Result, path string, depth int) error {

		bs, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		result, err := loadKnownTypes(path, bs, fl.metrics, fl.opts)
		if err != nil {
			if !isUnrecognizedFile(err) {
				return err
			}
			if depth > 0 {
				return nil
			}
			result, err = loadFileForAnyType(path, bs, fl.metrics, fl.opts)
			if err != nil {
				return err
			}
		}

		return curr.merge(path, result)
	})
}

// AsBundle loads a path as a bundle. If it is a single file
// it will be treated as a normal tarball bundle. If a directory
// is supplied it will be loaded as an unzipped bundle tree.
func (fl fileLoader) AsBundle(path string) (*bundle.Bundle, error) {
	path, err := fileurl.Clean(path)
	if err != nil {
		return nil, err
	}
	bundleLoader, isDir, err := GetBundleDirectoryLoader(path)
	if err != nil {
		return nil, err
	}

	br := bundle.NewCustomReader(bundleLoader).
		WithMetrics(fl.metrics).
		WithBundleVerificationConfig(fl.bvc).
		WithSkipBundleVerification(fl.skipVerify).
		WithProcessAnnotations(fl.opts.ProcessAnnotation)

	// For bundle directories add the full path in front of module file names
	// to simplify debugging.
	if isDir {
		br.WithBaseDir(path)
	}

	b, err := br.Read()
	if err != nil {
		err = fmt.Errorf("bundle %s: %w", path, err)
	}

	return &b, err
}

// GetBundleDirectoryLoader returns a bundle directory loader which can be used to load
// files in the directory.
func GetBundleDirectoryLoader(path string) (bundle.DirectoryLoader, bool, error) {
	path, err := fileurl.Clean(path)
	if err != nil {
		return nil, false, err
	}

	fi, err := os.Stat(path)
	if err != nil {
		return nil, false, fmt.Errorf("error reading %q: %s", path, err)
	}

	var bundleLoader bundle.DirectoryLoader

	if fi.IsDir() {
		bundleLoader = bundle.NewDirectoryLoader(path)
	} else {
		fh, err := os.Open(path)
		if err != nil {
			return nil, false, err
		}
		bundleLoader = bundle.NewTarballLoaderWithBaseURL(fh, path)
	}
	return bundleLoader, fi.IsDir(), nil
}

// FilteredPaths return a list of files from the specified
// paths while applying the given filters. If any filter returns true, the
// file/directory is excluded.
func FilteredPaths(paths []string, filter Filter) ([]string, error) {
	result := []string{}

	_, err := all(paths, filter, func(_ *Result, path string, _ int) error {
		result = append(result, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Schemas loads a schema set from the specified file path.
func Schemas(schemaPath string) (*ast.SchemaSet, error) {

	var errs Errors
	ss, err := loadSchemas(schemaPath)
	if err != nil {
		errs.add(err)
		return nil, errs
	}

	return ss, nil
}

func loadSchemas(schemaPath string) (*ast.SchemaSet, error) {

	if schemaPath == "" {
		return nil, nil
	}

	ss := ast.NewSchemaSet()
	path, err := fileurl.Clean(schemaPath)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	// Handle single file case.
	if !info.IsDir() {
		schema, err := loadOneSchema(path)
		if err != nil {
			return nil, err
		}
		ss.Put(ast.SchemaRootRef, schema)
		return ss, nil

	}

	// Handle directory case.
	rootDir := path

	err = filepath.Walk(path,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			} else if info.IsDir() {
				return nil
			}

			schema, err := loadOneSchema(path)
			if err != nil {
				return err
			}

			relPath, err := filepath.Rel(rootDir, path)
			if err != nil {
				return err
			}

			key := getSchemaSetByPathKey(relPath)
			ss.Put(key, schema)
			return nil
		})

	if err != nil {
		return nil, err
	}

	return ss, nil
}

func getSchemaSetByPathKey(path string) ast.Ref {

	front := filepath.Dir(path)
	last := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))

	var parts []string

	if front != "." {
		parts = append(strings.Split(filepath.ToSlash(front), "/"), last)
	} else {
		parts = []string{last}
	}

	key := make(ast.Ref, 1+len(parts))
	key[0] = ast.SchemaRootDocument
	for i := range parts {
		key[i+1] = ast.StringTerm(parts[i])
	}

	return key
}

func loadOneSchema(path string) (interface{}, error) {
	bs, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var schema interface{}
	if err := util.Unmarshal(bs, &schema); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	return schema, nil
}

// All returns a Result object loaded (recursively) from the specified paths.
// Deprecated: Use FileLoader.Filtered() instead.
func All(paths []string) (*Result, error) {
	return NewFileLoader().Filtered(paths, nil)
}

// Filtered returns a Result object loaded (recursively) from the specified
// paths while applying the given filters. If any filter returns true, the
// file/directory is excluded.
// Deprecated: Use FileLoader.Filtered() instead.
func Filtered(paths []string, filter Filter) (*Result, error) {
	return NewFileLoader().Filtered(paths, filter)
}

// AsBundle loads a path as a bundle. If it is a single file
// it will be treated as a normal tarball bundle. If a directory
// is supplied it will be loaded as an unzipped bundle tree.
// Deprecated: Use FileLoader.AsBundle() instead.
func AsBundle(path string) (*bundle.Bundle, error) {
	return NewFileLoader().AsBundle(path)
}

// AllRegos returns a Result object loaded (recursively) with all Rego source
// files from the specified paths.
func AllRegos(paths []string) (*Result, error) {
	return NewFileLoader().Filtered(paths, func(_ string, info os.FileInfo, depth int) bool {
		return !info.IsDir() && !strings.HasSuffix(info.Name(), bundle.RegoExt)
	})
}

// Rego is deprecated. Use RegoWithOpts instead.
func Rego(path string) (*RegoFile, error) {
	return RegoWithOpts(path, ast.ParserOptions{})
}

// RegoWithOpts returns a RegoFile object loaded from the given path.
func RegoWithOpts(path string, opts ast.ParserOptions) (*RegoFile, error) {
	path, err := fileurl.Clean(path)
	if err != nil {
		return nil, err
	}
	bs, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return loadRego(path, bs, metrics.New(), opts)
}

// CleanPath returns the normalized version of a path that can be used as an identifier.
func CleanPath(path string) string {
	return strings.Trim(path, "/")
}

// Paths returns a sorted list of files contained at path. If recurse is true
// and path is a directory, then Paths will walk the directory structure
// recursively and list files at each level.
func Paths(path string, recurse bool) (paths []string, err error) {
	path, err = fileurl.Clean(path)
	if err != nil {
		return nil, err
	}
	err = filepath.Walk(path, func(f string, info os.FileInfo, err error) error {
		if !recurse {
			if path != f && path != filepath.Dir(f) {
				return filepath.SkipDir
			}
		}
		paths = append(paths, f)
		return nil
	})
	return paths, err
}

// Dirs resolves filepaths to directories. It will return a list of unique
// directories.
func Dirs(paths []string) []string {
	unique := map[string]struct{}{}

	for _, path := range paths {
		// TODO: /dir/dir will register top level directory /dir
		dir := filepath.Dir(path)
		unique[dir] = struct{}{}
	}

	var u []string
	for k := range unique {
		u = append(u, k)
	}
	sort.Strings(u)
	return u
}

// SplitPrefix returns a tuple specifying the document prefix and the file
// path.
func SplitPrefix(path string) ([]string, string) {
	// Non-prefixed URLs can be returned without modification and their contents
	// can be rooted directly under data.
	if strings.Index(path, "://") == strings.Index(path, ":") {
		return nil, path
	}
	parts := strings.SplitN(path, ":", 2)
	if len(parts) == 2 && len(parts[0]) > 0 {
		return strings.Split(parts[0], "."), parts[1]
	}
	return nil, path
}

func (l *Result) merge(path string, result interface{}) error {
	switch result := result.(type) {
	case bundle.Bundle:
		for _, module := range result.Modules {
			l.Modules[module.Path] = &RegoFile{
				Name:   module.Path,
				Parsed: module.Parsed,
				Raw:    module.Raw,
			}
		}
		return l.mergeDocument(path, result.Data)
	case *RegoFile:
		l.Modules[CleanPath(path)] = result
		return nil
	default:
		return l.mergeDocument(path, result)
	}
}

func (l *Result) mergeDocument(path string, doc interface{}) error {
	obj, ok := makeDir(l.path, doc)
	if !ok {
		return unsupportedDocumentType(path)
	}
	merged, ok := merge.InterfaceMaps(l.Documents, obj)
	if !ok {
		return mergeError(path)
	}
	for k := range merged {
		l.Documents[k] = merged[k]
	}
	return nil
}

func (l *Result) withParent(p string) *Result {
	path := append(l.path, p)
	return &Result{
		Documents: l.Documents,
		Modules:   l.Modules,
		path:      path,
	}
}

func newResult() *Result {
	return &Result{
		Documents: map[string]interface{}{},
		Modules:   map[string]*RegoFile{},
	}
}

func all(paths []string, filter Filter, f func(*Result, string, int) error) (*Result, error) {
	errs := Errors{}
	root := newResult()

	for _, path := range paths {

		// Paths can be prefixed with a string that specifies where content should be
		// loaded under data. E.g., foo.bar:/path/to/some.json will load the content
		// of some.json under {"foo": {"bar": ...}}.
		loaded := root
		prefix, path := SplitPrefix(path)
		if len(prefix) > 0 {
			for _, part := range prefix {
				loaded = loaded.withParent(part)
			}
		}

		allRec(path, filter, &errs, loaded, 0, f)
	}

	if len(errs) > 0 {
		return nil, errs
	}

	return root, nil
}

func allRec(path string, filter Filter, errors *Errors, loaded *Result, depth int, f func(*Result, string, int) error) {

	path, err := fileurl.Clean(path)
	if err != nil {
		errors.add(err)
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		errors.add(err)
		return
	}

	if filter != nil && filter(path, info, depth) {
		return
	}

	if !info.IsDir() {
		if err := f(loaded, path, depth); err != nil {
			errors.add(err)
		}
		return
	}

	// If we are recursing on directories then content must be loaded under path
	// specified by directory hierarchy.
	if depth > 0 {
		loaded = loaded.withParent(info.Name())
	}

	files, err := ioutil.ReadDir(path)
	if err != nil {
		errors.add(err)
		return
	}

	for _, file := range files {
		allRec(filepath.Join(path, file.Name()), filter, errors, loaded, depth+1, f)
	}
}

func loadKnownTypes(path string, bs []byte, m metrics.Metrics, opts ast.ParserOptions) (interface{}, error) {
	switch filepath.Ext(path) {
	case ".json":
		return loadJSON(path, bs, m)
	case ".rego":
		return loadRego(path, bs, m, opts)
	case ".yaml", ".yml":
		return loadYAML(path, bs, m)
	default:
		if strings.HasSuffix(path, ".tar.gz") {
			r, err := loadBundleFile(path, bs, m)
			if err != nil {
				err = fmt.Errorf("bundle %s: %w", path, err)
			}
			return r, err
		}
	}
	return nil, unrecognizedFile(path)
}

func loadFileForAnyType(path string, bs []byte, m metrics.Metrics, opts ast.ParserOptions) (interface{}, error) {
	module, err := loadRego(path, bs, m, opts)
	if err == nil {
		return module, nil
	}
	doc, err := loadJSON(path, bs, m)
	if err == nil {
		return doc, nil
	}
	doc, err = loadYAML(path, bs, m)
	if err == nil {
		return doc, nil
	}
	return nil, unrecognizedFile(path)
}

func loadBundleFile(path string, bs []byte, m metrics.Metrics) (bundle.Bundle, error) {
	tl := bundle.NewTarballLoaderWithBaseURL(bytes.NewBuffer(bs), path)
	br := bundle.NewCustomReader(tl).WithMetrics(m).WithSkipBundleVerification(true).IncludeManifestInData(true)
	return br.Read()
}

func loadRego(path string, bs []byte, m metrics.Metrics, opts ast.ParserOptions) (*RegoFile, error) {
	m.Timer(metrics.RegoModuleParse).Start()
	var module *ast.Module
	var err error
	module, err = ast.ParseModuleWithOpts(path, string(bs), opts)
	m.Timer(metrics.RegoModuleParse).Stop()
	if err != nil {
		return nil, err
	}
	result := &RegoFile{
		Name:   path,
		Parsed: module,
		Raw:    bs,
	}
	return result, nil
}

func loadJSON(path string, bs []byte, m metrics.Metrics) (interface{}, error) {
	m.Timer(metrics.RegoDataParse).Start()
	buf := bytes.NewBuffer(bs)
	decoder := util.NewJSONDecoder(buf)
	var x interface{}
	err := decoder.Decode(&x)
	m.Timer(metrics.RegoDataParse).Stop()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return x, nil
}

func loadYAML(path string, bs []byte, m metrics.Metrics) (interface{}, error) {
	m.Timer(metrics.RegoDataParse).Start()
	bs, err := yaml.YAMLToJSON(bs)
	m.Timer(metrics.RegoDataParse).Stop()
	if err != nil {
		return nil, fmt.Errorf("%v: error converting YAML to JSON: %v", path, err)
	}
	return loadJSON(path, bs, m)
}

func makeDir(path []string, x interface{}) (map[string]interface{}, bool) {
	if len(path) == 0 {
		obj, ok := x.(map[string]interface{})
		if !ok {
			return nil, false
		}
		return obj, true
	}
	return makeDir(path[:len(path)-1], map[string]interface{}{path[len(path)-1]: x})
}
