package resolver

import (
	"github.com/aquasecurity/trivy/pkg/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/scanners/azure/expressions"
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Resolver interface {
	ResolveExpression(expression azure.Value) azure.Value
	SetDeployment(d *azure.Deployment)
}

func NewResolver() Resolver {
	return &resolver{}
}

type resolver struct {
	deployment *azure.Deployment
}

func (r *resolver) SetDeployment(d *azure.Deployment) {
	r.deployment = d
}

func (r *resolver) ResolveExpression(expression azure.Value) azure.Value {
	if expression.Kind != azure.KindExpression {
		return expression
	}
	if r.deployment == nil {
		panic("cannot resolve expression on nil deployment")
	}
	code := expression.AsString()

	resolved, err := r.resolveExpressionString(code, expression.GetMetadata())
	if err != nil {
		expression.Kind = azure.KindUnresolvable
		return expression
	}
	return resolved
}

func (r *resolver) resolveExpressionString(code string, metadata defsecTypes.MisconfigMetadata) (azure.Value, error) {
	et, err := expressions.NewExpressionTree(code)
	if err != nil {
		return azure.NullValue, err
	}

	evaluatedValue := et.Evaluate(r.deployment)
	return azure.NewValue(evaluatedValue, metadata), nil
}
