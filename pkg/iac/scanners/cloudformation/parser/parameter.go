package parser

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"strconv"
	"strings"

	"encoding/json/v2"
	"encoding/json/jsontext"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

type Parameter struct {
	// TODO: remove inner
	inner parameterInner
}

type parameterInner struct {
	Type    string `yaml:"Type"`
	Default any    `yaml:"Default"`
}

func (p *Parameter) UnmarshalYAML(node *yaml.Node) error {
	return node.Decode(&p.inner)
}

func (p *Parameter) UnmarshalJSONFrom(dec *jsontext.Decoder) error {

	var inner parameterInner

	if err := json.UnmarshalDecode(dec, &inner,
		json.WithUnmarshalers(json.UnmarshalFromFunc(unmarshalIntFirst)),
	); err != nil {
		return err
	}

	p.inner = inner
	return nil
}

func unmarshalIntFirst(dec *jsontext.Decoder, v *any) error {
	if dec.PeekKind() == '0' {
		if jval, err := dec.ReadValue(); err != nil {
			return err
		} else if v1, err := strconv.ParseInt(string(jval), 10, 64); err == nil {
			*v = int(v1)
		} else if v1, err := strconv.ParseFloat(string(jval), 64); err == nil {
			*v = v1
		}
		return nil
	}
	return json.SkipFunc
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
	maps.Copy((*p), other)
}

func (p *Parameters) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	(*p) = make(Parameters)

	switch d.PeekKind() {
	case '{':
		// CodePipeline like format
		var params struct {
			Params map[string]any `json:"Parameters"`
		}

		if err := json.UnmarshalDecode(d, &params); err != nil {
			return err
		}

		(*p) = params.Params
	case '[':
		// Original format
		var params []string

		jval, err := d.ReadValue()
		if err != nil {
			return err
		}

		if err := json.Unmarshal(jval, &params); err == nil {
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

		if err := json.Unmarshal(jval, &cfparams, json.RejectUnknownMembers(true)); err != nil {
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

func ParseParameters(r io.Reader) (Parameters, error) {
	var parameters Parameters
	if err := json.UnmarshalRead(r, &parameters); err != nil {
		return nil, err
	}
	return parameters, nil
}
