package parser

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"strconv"
	"strings"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

type Parameter struct {
	Typ     string
	Default any
}

func (p *Parameter) Type() cftypes.CfType {
	switch p.Typ {
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

func (p *Parameter) UpdateDefault(inVal any) {
	passedVal := inVal.(string)

	switch p.Typ {
	case "Boolean":
		p.Default, _ = strconv.ParseBool(passedVal)
	case "String":
		p.Default = passedVal
	case "Integer":
		p.Default, _ = strconv.Atoi(passedVal)
	default:
		p.Default = passedVal
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
