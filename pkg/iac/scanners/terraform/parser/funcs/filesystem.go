// Copied from github.com/hashicorp/terraform/internal/lang/funcs
package funcs

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"unicode/utf8"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/mitchellh/go-homedir"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// MakeFileFunc constructs a function that takes a file path and returns the
// contents of that file, either directly as a string (where valid UTF-8 is
// required) or as a string containing base64 bytes.
func MakeFileFunc(target fs.FS, baseDir string, encBase64 bool) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{
				Name: "path",
				Type: cty.String,
			},
		},
		Type: function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			path := args[0].AsString()
			src, err := readFileBytes(target, baseDir, path)
			if err != nil {
				err = function.NewArgError(0, err)
				return cty.UnknownVal(cty.String), err
			}

			switch {
			case encBase64:
				enc := base64.StdEncoding.EncodeToString(src)
				return cty.StringVal(enc), nil
			default:
				if !utf8.Valid(src) {
					return cty.UnknownVal(cty.String), fmt.Errorf("contents of %s are not valid UTF-8; use the filebase64 function to obtain the Base64 encoded contents or the other file functions (e.g. filemd5, filesha256) to obtain file hashing results instead", path)
				}
				return cty.StringVal(string(src)), nil
			}
		},
	})
}

// MakeTemplateFileFunc constructs a function that takes a file path and
// an arbitrary object of named values and attempts to render the referenced
// file as a template using HCL template syntax.
//
// The template itself may recursively call other functions so a callback
// must be provided to get access to those functions. The template cannot,
// however, access any variables defined in the scope: it is restricted only to
// those variables provided in the second function argument, to ensure that all
// dependencies on other graph nodes can be seen before executing this function.
//
// As a special exception, a referenced template file may not recursively call
// the templatefile function, since that would risk the same file being
// included into itself indefinitely.
func MakeTemplateFileFunc(target fs.FS, baseDir string, funcsCb func() map[string]function.Function) function.Function {

	params := []function.Parameter{
		{
			Name: "path",
			Type: cty.String,
		},
		{
			Name: "vars",
			Type: cty.DynamicPseudoType,
		},
	}

	loadTmpl := func(fn string) (hcl.Expression, error) {
		// We re-use File here to ensure the same filename interpretation
		// as it does, along with its other safety checks.
		tmplVal, err := File(target, baseDir, cty.StringVal(fn))
		if err != nil {
			return nil, err
		}

		expr, diags := hclsyntax.ParseTemplate([]byte(tmplVal.AsString()), fn, hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			return nil, diags
		}

		return expr, nil
	}

	renderTmpl := func(expr hcl.Expression, varsVal cty.Value) (cty.Value, error) {
		if varsTy := varsVal.Type(); !(varsTy.IsMapType() || varsTy.IsObjectType()) {
			return cty.DynamicVal, function.NewArgErrorf(1, "invalid vars value: must be a map") // or an object, but we don't strongly distinguish these most of the time
		}

		ctx := &hcl.EvalContext{
			Variables: varsVal.AsValueMap(),
		}

		// We require all of the variables to be valid HCL identifiers, because
		// otherwise there would be no way to refer to them in the template
		// anyway. Rejecting this here gives better feedback to the user
		// than a syntax error somewhere in the template itself.
		for n := range ctx.Variables {
			if !hclsyntax.ValidIdentifier(n) {
				// This error message intentionally doesn't describe _all_ of
				// the different permutations that are technically valid as an
				// HCL identifier, but rather focuses on what we might
				// consider to be an "idiomatic" variable name.
				return cty.DynamicVal, function.NewArgErrorf(1, "invalid template variable name %q: must start with a letter, followed by zero or more letters, digits, and underscores", n)
			}
		}

		// We'll pre-check references in the template here so we can give a
		// more specialized error message than HCL would by default, so it's
		// clearer that this problem is coming from a templatefile call.
		for _, traversal := range expr.Variables() {
			root := traversal.RootName()
			if _, ok := ctx.Variables[root]; !ok {
				return cty.DynamicVal, function.NewArgErrorf(1, "vars map does not contain key %q, referenced at %s", root, traversal[0].SourceRange())
			}
		}

		givenFuncs := funcsCb() // this callback indirection is to avoid chicken/egg problems
		funcs := make(map[string]function.Function, len(givenFuncs))
		for name, fn := range givenFuncs {
			if name == "templatefile" {
				// We stub this one out to prevent recursive calls.
				funcs[name] = function.New(&function.Spec{
					Params: params,
					Type: func(args []cty.Value) (cty.Type, error) {
						return cty.NilType, errors.New("cannot recursively call templatefile from inside templatefile call")
					},
				})
				continue
			}
			funcs[name] = fn
		}
		ctx.Functions = funcs

		val, diags := expr.Value(ctx)
		if diags.HasErrors() {
			return cty.DynamicVal, diags
		}
		return val, nil
	}

	return function.New(&function.Spec{
		Params: params,
		Type: func(args []cty.Value) (cty.Type, error) {
			if !(args[0].IsKnown() && args[1].IsKnown()) {
				return cty.DynamicPseudoType, nil
			}

			// We'll render our template now to see what result type it produces.
			// A template consisting only of a single interpolation an potentially
			// return any type.
			expr, err := loadTmpl(args[0].AsString())
			if err != nil {
				return cty.DynamicPseudoType, err
			}

			// This is safe even if args[1] contains unknowns because the HCL
			// template renderer itself knows how to short-circuit those.
			val, err := renderTmpl(expr, args[1])
			return val.Type(), err
		},
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			expr, err := loadTmpl(args[0].AsString())
			if err != nil {
				return cty.DynamicVal, err
			}
			return renderTmpl(expr, args[1])
		},
	})

}

// MakeFileExistsFunc constructs a function that takes a path
// and determines whether a file exists at that path
func MakeFileExistsFunc(target fs.FS, baseDir string) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{
				Name: "path",
				Type: cty.String,
			},
		},
		Type: function.StaticReturnType(cty.Bool),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			path := args[0].AsString()
			path, err := homedir.Expand(path)
			if err != nil {
				return cty.UnknownVal(cty.Bool), fmt.Errorf("failed to expand ~: %s", err)
			}

			if !filepath.IsAbs(path) {
				path = filepath.Join(baseDir, path)
			}

			// Trivy uses a virtual file system
			path = filepath.ToSlash(path)

			fi, err := fs.Stat(target, path)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return cty.False, nil
				}
				return cty.UnknownVal(cty.Bool), fmt.Errorf("failed to stat %s", path)
			}

			if fi.Mode().IsRegular() {
				return cty.True, nil
			}

			return cty.False, fmt.Errorf("%s is not a regular file, but %q",
				path, fi.Mode().String())
		},
	})
}

// MakeFileSetFunc constructs a function that takes a glob pattern
// and enumerates a file set from that pattern
func MakeFileSetFunc(target fs.FS, baseDir string) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{
				Name: "path",
				Type: cty.String,
			},
			{
				Name: "pattern",
				Type: cty.String,
			},
		},
		Type: function.StaticReturnType(cty.Set(cty.String)),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			path := args[0].AsString()
			pattern := args[1].AsString()

			if !filepath.IsAbs(path) {
				path = filepath.Join(baseDir, path)
			}

			// Join the path to the glob pattern, and ensure both path and pattern
			// agree on path separators, so the globbing works as expected.
			pattern = filepath.ToSlash(filepath.Join(path, pattern))
			path = filepath.ToSlash(path)

			matches, err := doublestar.Glob(target, pattern)
			if err != nil {
				return cty.UnknownVal(cty.Set(cty.String)), fmt.Errorf("failed to glob pattern (%s): %s", pattern, err)
			}

			var matchVals []cty.Value
			for _, match := range matches {
				fi, err := fs.Stat(target, match)

				if err != nil {
					return cty.UnknownVal(cty.Set(cty.String)), fmt.Errorf("failed to stat (%s): %s", match, err)
				}

				if !fi.Mode().IsRegular() {
					continue
				}

				// Remove the path and file separator from matches.
				match, err = filepath.Rel(path, match)

				if err != nil {
					return cty.UnknownVal(cty.Set(cty.String)), fmt.Errorf("failed to trim path of match (%s): %s", match, err)
				}

				// Replace any remaining file separators with forward slash (/)
				// separators for cross-system compatibility.
				match = filepath.ToSlash(match)

				matchVals = append(matchVals, cty.StringVal(match))
			}

			if len(matchVals) == 0 {
				return cty.SetValEmpty(cty.String), nil
			}

			return cty.SetVal(matchVals), nil
		},
	})
}

// BasenameFunc constructs a function that takes a string containing a filesystem path
// and removes all except the last portion from it.
var BasenameFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{
			Name: "path",
			Type: cty.String,
		},
	},
	Type: function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		return cty.StringVal(filepath.Base(args[0].AsString())), nil
	},
})

// DirnameFunc constructs a function that takes a string containing a filesystem path
// and removes the last portion from it.
var DirnameFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{
			Name: "path",
			Type: cty.String,
		},
	},
	Type: function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		return cty.StringVal(filepath.Dir(args[0].AsString())), nil
	},
})

// AbsPathFunc constructs a function that converts a filesystem path to an absolute path
var AbsPathFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{
			Name: "path",
			Type: cty.String,
		},
	},
	Type: function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		absPath, err := filepath.Abs(args[0].AsString())
		return cty.StringVal(filepath.ToSlash(absPath)), err
	},
})

// PathExpandFunc constructs a function that expands a leading ~ character to the current user's home directory.
var PathExpandFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{
			Name: "path",
			Type: cty.String,
		},
	},
	Type: function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {

		homePath, err := homedir.Expand(args[0].AsString())
		return cty.StringVal(homePath), err
	},
})

func openFile(target fs.FS, baseDir, path string) (fs.File, error) {
	path, err := homedir.Expand(path)
	if err != nil {
		return nil, fmt.Errorf("failed to expand ~: %s", err)
	}

	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}

	// Trivy uses a virtual file system
	path = filepath.ToSlash(path)

	if target != nil {
		return target.Open(path)
	}
	return os.Open(path)
}

func readFileBytes(target fs.FS, baseDir, path string) ([]byte, error) {
	f, err := openFile(target, baseDir, path)
	if err != nil {
		if os.IsNotExist(err) {
			// An extra Terraform-specific hint for this situation
			return nil, fmt.Errorf("no file exists at %s; this function works only with files that are distributed as part of the configuration source code, so if this file will be created by a resource in this configuration you must instead obtain this result from an attribute of that resource", path)
		}
		return nil, err
	}

	src, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s", path)
	}

	return src, nil
}

// File reads the contents of the file at the given path.
//
// The file must contain valid UTF-8 bytes, or this function will return an error.
//
// The underlying function implementation works relative to a particular base
// directory, so this wrapper takes a base directory string and uses it to
// construct the underlying function before calling it.
func File(target fs.FS, baseDir string, path cty.Value) (cty.Value, error) {
	fn := MakeFileFunc(target, baseDir, false)
	return fn.Call([]cty.Value{path})
}
