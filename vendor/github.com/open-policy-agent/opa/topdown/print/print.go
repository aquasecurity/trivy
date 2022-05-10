package print

import (
	"context"

	"github.com/open-policy-agent/opa/ast"
)

// Context provides the Hook implementation context about the print() call.
type Context struct {
	Context  context.Context // request context passed when query executed
	Location *ast.Location   // location of print call
}

// Hook defines the interface that callers can implement to receive print
// statement outputs. If the hook returns an error, it will be surfaced if
// strict builtin error checking is enabled (otherwise, it will not halt
// execution.)
type Hook interface {
	Print(Context, string) error
}
