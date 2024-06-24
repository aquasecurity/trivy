package rego

import (
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"

	checksrego "github.com/aquasecurity/trivy-checks/pkg/rego"
)

func init() {

	checksrego.RegisterBuiltins()

	rego.RegisterBuiltin2(&rego.Function{
		Name: "result.new",
		Decl: types.NewFunction(types.Args(types.S, types.A), types.A),
	},
		createResult,
	)

	rego.RegisterBuiltin1(&rego.Function{
		Name: "isManaged",
		Decl: types.NewFunction(types.Args(types.A), types.B),
	},
		func(c rego.BuiltinContext, resource *ast.Term) (*ast.Term, error) {
			metadata, err := createResult(c, ast.StringTerm(""), resource)
			if err != nil {
				return nil, err
			}
			return metadata.Get(ast.StringTerm("managed")), nil
		},
	)
}

func createResult(ctx rego.BuiltinContext, msg, cause *ast.Term) (*ast.Term, error) {

	metadata := map[string]*ast.Term{
		"startline":    ast.IntNumberTerm(0),
		"endline":      ast.IntNumberTerm(0),
		"sourceprefix": ast.StringTerm(""),
		"filepath":     ast.StringTerm(""),
		"explicit":     ast.BooleanTerm(false),
		"managed":      ast.BooleanTerm(true),
		"fskey":        ast.StringTerm(""),
		"resource":     ast.StringTerm(""),
		"parent":       ast.NullTerm(),
	}
	if msg != nil {
		metadata["msg"] = msg
	}

	// universal
	input := cause.Get(ast.StringTerm("__defsec_metadata"))
	if input == nil {
		// docker
		input = cause
	}
	metadata = updateMetadata(metadata, input)

	if term := input.Get(ast.StringTerm("parent")); term != nil {
		var err error
		metadata["parent"], err = createResult(ctx, nil, term)
		if err != nil {
			return nil, err
		}
	}

	var values [][2]*ast.Term
	for key, val := range metadata {
		values = append(values, [2]*ast.Term{
			ast.StringTerm(key),
			val,
		})
	}
	return ast.ObjectTerm(values...), nil
}

func updateMetadata(metadata map[string]*ast.Term, input *ast.Term) map[string]*ast.Term {
	if term := input.Get(ast.StringTerm("startline")); term != nil {
		metadata["startline"] = term
	}
	if term := input.Get(ast.StringTerm("StartLine")); term != nil {
		metadata["startline"] = term
	}
	if term := input.Get(ast.StringTerm("endline")); term != nil {
		metadata["endline"] = term
	}
	if term := input.Get(ast.StringTerm("EndLine")); term != nil {
		metadata["endline"] = term
	}
	if term := input.Get(ast.StringTerm("filepath")); term != nil {
		metadata["filepath"] = term
	}
	if term := input.Get(ast.StringTerm("sourceprefix")); term != nil {
		metadata["sourceprefix"] = term
	}
	if term := input.Get(ast.StringTerm("Path")); term != nil {
		metadata["filepath"] = term
	}
	if term := input.Get(ast.StringTerm("explicit")); term != nil {
		metadata["explicit"] = term
	}
	if term := input.Get(ast.StringTerm("managed")); term != nil {
		metadata["managed"] = term
	}
	if term := input.Get(ast.StringTerm("fskey")); term != nil {
		metadata["fskey"] = term
	}
	if term := input.Get(ast.StringTerm("resource")); term != nil {
		metadata["resource"] = term
	}
	return metadata
}
