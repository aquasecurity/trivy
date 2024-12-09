package snapshot

import (
	"errors"
	"fmt"
	"io"

	"github.com/zclconf/go-cty/cty"
	ctymsgpack "github.com/zclconf/go-cty/cty/msgpack"
	"google.golang.org/protobuf/proto"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraformplan/snapshot/planproto"
)

type DynamicValue []byte

func (v DynamicValue) Decode(ty cty.Type) (cty.Value, error) {
	if v == nil {
		return cty.NilVal, nil
	}

	return ctymsgpack.Unmarshal([]byte(v), ty)
}

type Plan struct {
	variableValues map[string]DynamicValue
}

func (p Plan) inputVariables() (map[string]cty.Value, error) {
	vars := make(map[string]cty.Value)
	for k, v := range p.variableValues {
		val, err := v.Decode(cty.DynamicPseudoType)
		if err != nil {
			return nil, err
		}
		vars[k] = val
	}
	return vars, nil
}

func readTfPlan(r io.Reader) (*Plan, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read plan: %w", err)
	}

	var rawPlan planproto.Plan
	if err := proto.Unmarshal(b, &rawPlan); err != nil {
		return nil, fmt.Errorf("failed to unmarshal plan: %w", err)
	}

	plan := Plan{
		variableValues: make(map[string]DynamicValue),
	}

	for k, v := range rawPlan.Variables {
		if len(v.Msgpack) == 0 { // len(0) because that's the default value for a "bytes" in protobuf
			return nil, errors.New("dynamic value does not have msgpack serialization")
		}

		plan.variableValues[k] = DynamicValue(v.Msgpack)
	}

	return &plan, nil
}
