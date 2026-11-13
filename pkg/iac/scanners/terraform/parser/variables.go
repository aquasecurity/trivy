package parser

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/typeexpr"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"

	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func loadTFVars(srcFS fs.FS, filenames []string) (map[string]cty.Value, error) {
	combinedVars := make(map[string]cty.Value)

	for _, env := range os.Environ() {
		split := strings.Split(env, "=")
		key := split[0]
		if !strings.HasPrefix(key, "TF_VAR_") {
			continue
		}
		key = strings.TrimPrefix(key, "TF_VAR_")
		var val string
		if len(split) > 1 {
			val = split[1]
		}
		combinedVars[key] = cty.StringVal(val)
	}

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

// variableValue returns the value of the variable from inputs or from its default,
// converted to the variable type.
func variableValue(b *terraform.Block, inputs map[string]cty.Value) (cty.Value, error) {
	if b.Label() == "" {
		return cty.NilVal, errors.New("empty label - cannot resolve")
	}

	attributes := b.Attributes()

	var valType cty.Type
	var defaults *typeexpr.Defaults
	if typeAttr, exists := attributes["type"]; exists {
		ty, def, err := typeAttr.DecodeVarType()
		if err != nil {
			return cty.NilVal, err
		}
		valType = ty
		defaults = def
	}

	var val cty.Value

	if override, exists := inputs[b.Label()]; exists && override.Type() != cty.NilType {
		val = override
	} else if def, exists := attributes["default"]; exists {
		val = def.NullableValue()
	} else {
		return cty.NilVal, errors.New("no value found")
	}

	if valType != cty.NilType {
		if defaults != nil {
			val = defaults.Apply(val)
		}

		typedVal, err := convert.Convert(val, valType)
		if err != nil {
			return cty.NilVal, err
		}
		return typedVal, nil
	}

	return val, nil

}
