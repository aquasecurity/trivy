package parser

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/liamg/jfather"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

type Parameter struct {
	inner parameterInner
}

type parameterInner struct {
	Type    string `yaml:"Type"`
	Default any    `yaml:"Default"`
}

func (p *Parameter) UnmarshalYAML(node *yaml.Node) error {
	return node.Decode(&p.inner)
}

func (p *Parameter) UnmarshalJSONWithMetadata(node jfather.Node) error {

	var inner parameterInner

	if err := node.Decode(&inner); err != nil {
		return err
	}

	// jfather parses Number without fraction as int64
	// https://github.com/liamg/jfather/blob/4ef05d70c05af167226d3333a4ec7d8ac3c9c281/parse_number.go#L33-L42
	switch v := inner.Default.(type) {
	case int64:
		inner.Default = int(v)
	default:
		inner.Default = v
	}

	p.inner = inner
	return nil
}

func (p *Parameter) Type() cftypes.CfType {
	switch p.inner.Type {
	case "Boolean":
		return cftypes.Bool
	case "String":
		return cftypes.String
	case "Integer":
		return cftypes.Int
	default:
		return cftypes.String
	}
}

func (p *Parameter) Default() any {
	return p.inner.Default
}

func (p *Parameter) UpdateDefault(inVal any) {
	passedVal := inVal.(string)

	switch p.inner.Type {
	case "Boolean":
		p.inner.Default, _ = strconv.ParseBool(passedVal)
	case "String":
		p.inner.Default = passedVal
	case "Integer":
		p.inner.Default, _ = strconv.Atoi(passedVal)
	default:
		p.inner.Default = passedVal
	}
}

type Parameters map[string]any

func (p *Parameters) Merge(other Parameters) {
	for k, v := range other {
		(*p)[k] = v
	}
}

func (p *Parameters) UnmarshalJSON(data []byte) error {
	(*p) = make(Parameters)

	if len(data) == 0 {
		return nil
	}

	switch {
	case data[0] == '{' && data[len(data)-1] == '}': // object
		// CodePipeline like format
		var params struct {
			Params map[string]any `json:"Parameters"`
		}

		if err := json.Unmarshal(data, &params); err != nil {
			return err
		}

		(*p) = params.Params
	case data[0] == '[' && data[len(data)-1] == ']': // array
		// Original format
		var params []string

		if err := json.Unmarshal(data, &params); err == nil {
			for _, param := range params {
				parts := strings.Split(param, "=")
				if len(parts) != 2 {
					return fmt.Errorf("invalid key-value parameter: %q", param)
				}
				(*p)[parts[0]] = parts[1]
			}
			return nil
		}

		// CloudFormation like format
		var cfparams []struct {
			ParameterKey   string `json:"ParameterKey"`
			ParameterValue string `json:"ParameterValue"`
		}

		d := json.NewDecoder(bytes.NewReader(data))
		d.DisallowUnknownFields()
		if err := d.Decode(&cfparams); err != nil {
			return err
		}

		for _, param := range cfparams {
			(*p)[param.ParameterKey] = param.ParameterValue
		}
	default:
		return errors.New("unsupported parameters format")
	}

	return nil
}
