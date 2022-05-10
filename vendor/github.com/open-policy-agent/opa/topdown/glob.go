package topdown

import (
	"fmt"
	"sync"

	"github.com/gobwas/glob"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/builtins"
)

var globCacheLock = sync.Mutex{}
var globCache map[string]glob.Glob

func builtinGlobMatch(a, b, c ast.Value) (ast.Value, error) {
	pattern, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	delimiters, err := builtins.RuneSliceOperand(b, 2)
	if err != nil {
		return nil, err
	}

	if len(delimiters) == 0 {
		delimiters = []rune{'.'}
	}

	match, err := builtins.StringOperand(c, 3)
	if err != nil {
		return nil, err
	}

	id := fmt.Sprintf("%s-%v", pattern, delimiters)

	globCacheLock.Lock()
	defer globCacheLock.Unlock()
	p, ok := globCache[id]
	if !ok {
		var err error
		if p, err = glob.Compile(string(pattern), delimiters...); err != nil {
			return nil, err
		}
		globCache[id] = p
	}

	return ast.Boolean(p.Match(string(match))), nil
}

func builtinGlobQuoteMeta(a ast.Value) (ast.Value, error) {
	pattern, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	return ast.String(glob.QuoteMeta(string(pattern))), nil
}

func init() {
	globCache = map[string]glob.Glob{}
	RegisterFunctionalBuiltin3(ast.GlobMatch.Name, builtinGlobMatch)
	RegisterFunctionalBuiltin1(ast.GlobQuoteMeta.Name, builtinGlobQuoteMeta)
}
