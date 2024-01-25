package expressions

import (
	"github.com/aquasecurity/trivy/pkg/scanners/azure/functions"
)

type Node interface {
	Evaluate(deploymentProvider functions.DeploymentData) interface{}
}

type expressionValue struct {
	val interface{}
}

func (e expressionValue) Evaluate(deploymentProvider functions.DeploymentData) interface{} {
	if f, ok := e.val.(expression); ok {
		return f.Evaluate(deploymentProvider)
	}
	return e.val
}

type expression struct {
	name string
	args []Node
}

func (f expression) Evaluate(deploymentProvider functions.DeploymentData) interface{} {
	args := make([]interface{}, len(f.args))
	for i, arg := range f.args {
		args[i] = arg.Evaluate(deploymentProvider)
	}

	return functions.Evaluate(deploymentProvider, f.name, args...)
}

func NewExpressionTree(code string) (Node, error) {
	tokens, err := lex(code)
	if err != nil {
		return nil, err
	}

	// create a walker for the nodes
	tw := newTokenWalker(tokens)

	// generate the root function
	return newFunctionNode(tw), nil
}

func newFunctionNode(tw *tokenWalker) Node {
	funcNode := &expression{
		name: tw.pop().Data.(string),
	}

	for tw.hasNext() {
		token := tw.pop()
		if token == nil {
			break
		}

		switch token.Type {
		case TokenCloseParen:
			return funcNode
		case TokenName:
			if tw.peek().Type == TokenOpenParen {
				//  this is a function, unwind 1
				tw.unPop()
				funcNode.args = append(funcNode.args, newFunctionNode(tw))
			}
		case TokenLiteralString, TokenLiteralInteger, TokenLiteralFloat:
			funcNode.args = append(funcNode.args, expressionValue{token.Data})
		}

	}
	return funcNode
}
