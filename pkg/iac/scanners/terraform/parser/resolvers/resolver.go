package resolvers

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/aquasecurity/trivy/pkg/log"
)

// ErrNotApplicable is returned by a resolver that does not handle the given module source.
var ErrNotApplicable = errors.New("resolver is not applicable")

// Result describes a module resolved by one of the resolvers.
type Result struct {
	// FS is the filesystem the module was resolved to.
	FS fs.FS
	// SourcePrefix is the module source, such as
	// "git::https://github.com/org/repo". It is empty for local modules.
	SourcePrefix string
	// Dir is the module directory within FS.
	Dir string
}

// ModuleResolver resolves a module from a specific kind of source.
// It returns [ErrNotApplicable] if it does not handle the given source.
type ModuleResolver interface {
	Resolve(context.Context, fs.FS, Options) (Result, error)
}

var defaultResolvers = []ModuleResolver{
	Local,
	Cache,
	Remote,
	Registry,
}

// Resolve locates the module described by opt, trying each resolver in turn.
func Resolve(ctx context.Context, current fs.FS, opt Options) (Result, error) {
	opt.Logger.Debug("Resolving module",
		log.String("name", opt.Name), log.String("source", opt.Source))
	for _, resolver := range defaultResolvers {
		res, err := resolver.Resolve(ctx, current, opt)
		if errors.Is(err, ErrNotApplicable) {
			continue
		} else if err != nil {
			return Result{}, err
		}
		opt.Logger.Debug("Module resolved", log.FilePath(res.Dir))
		return res, nil
	}
	return Result{}, fmt.Errorf("failed to resolve module '%s' with source: %s", opt.Name, opt.Source)
}
