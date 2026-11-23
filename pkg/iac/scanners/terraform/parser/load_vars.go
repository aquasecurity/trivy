package parser

import (
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/log"
)

func parseEnvVar(name, val string, ty cty.Type) (cty.Value, error) {
	if ty == cty.NilType || ty.IsPrimitiveType() {
		return cty.StringVal(val), nil
	}
	expr, diags := hclsyntax.ParseExpression([]byte(val), "<TF_VAR_"+name+">", hcl.InitialPos)
	if diags.HasErrors() {
		return cty.NilVal, fmt.Errorf("parse HCL expression: %w", diags)
	}
	v, diags := expr.Value(nil)
	if diags.HasErrors() {
		return cty.NilVal, fmt.Errorf("evaluate HCL expression: %w", diags)
	}
	return v, nil
}

func loadEnvVars(logger *log.Logger, blocks terraform.Blocks) map[string]cty.Value {
	envVars := make(map[string]cty.Value)
	varTypes := make(map[string]cty.Type)

	for _, block := range blocks.OfType("variable") {
		varTypes[block.TypeLabel()] = inputVariableType(block)
	}

	for _, env := range os.Environ() {
		key, val, _ := strings.Cut(env, "=")
		name, ok := strings.CutPrefix(key, "TF_VAR_")
		if !ok {
			continue
		}
		v, err := parseEnvVar(name, val, varTypes[name])
		if err != nil {
			logger.Warn("Ignoring TF_VAR environment variable", log.String("name", "TF_VAR_"+name), log.Err(err))
			continue
		}
		envVars[name] = v
	}

	return envVars
}

func loadTFVars(srcFS fs.FS, filenames []string) (map[string]cty.Value, error) {
	combinedVars := make(map[string]cty.Value)

	for _, filename := range filenames {
		vars, err := loadTFVarsFile(srcFS, filename)
		if err != nil {
			return nil, fmt.Errorf("failed to load tfvars from %s: %w", filename, err)
		}
		maps.Copy(combinedVars, vars)
	}

	return combinedVars, nil
}

func loadTFVarsFile(srcFS fs.FS, filename string) (map[string]cty.Value, error) {
	inputVars := make(map[string]cty.Value)
	if filename == "" {
		return inputVars, nil
	}

	src, err := fs.ReadFile(srcFS, filepath.ToSlash(filename))
	if err != nil {
		return nil, err
	}

	var attrs hcl.Attributes
	if strings.HasSuffix(filename, ".json") {
		variableFile, err := hcljson.Parse(src, filename)
		if err != nil {
			return nil, err
		}
		attrs, err = variableFile.Body.JustAttributes()
		if err != nil {
			return nil, err
		}
	} else {
		variableFile, err := hclsyntax.ParseConfig(src, filename, hcl.Pos{Line: 1, Column: 1})
		if err != nil {
			return nil, err
		}
		attrs, err = variableFile.Body.JustAttributes()
		if err != nil {
			return nil, err
		}
	}

	for _, attr := range attrs {
		inputVars[attr.Name], _ = attr.Expr.Value(&hcl.EvalContext{})
	}

	return inputVars, nil
}
