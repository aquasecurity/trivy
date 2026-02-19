package eval

import (
	"context"
	"io/fs"
	"os"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/zclconf/go-cty/cty"
)

func Eval(ctx context.Context, fsys fs.FS, root string, opts *EvalOpts) (*graphEvaluator, error) {
	if opts == nil {
		opts = &EvalOpts{
			Workspace: "default",
		}
	}

	if opts.WorkDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		opts.WorkDir = wd
	}

	if opts.InputVars == nil {
		opts.InputVars = make(map[string]cty.Value)
	}

	if opts.Logger == nil {
		opts.Logger = log.WithPrefix("tf-eval")
	}

	modResolver := newModuleResolver(
		opts.Logger.With(log.Prefix("module-resolver")),
		WithAllowDownloads(opts.AllowDownloads),
		WithSkipCachedModules(opts.SkipCachedModules),
		WithStopOnHCLError(opts.StopOnHCLError),
		WithSkipPaths(opts.SkipPaths),
	)

	rootMod, err := modResolver.resolve(ctx, fsys, root)
	if err != nil {
		return nil, err
	}

	g := newGraph()
	if err := g.build(rootMod); err != nil {
		return nil, err
	}

	e := newEvaluator(g, rootMod, opts)
	if err := e.evalGraph(); err != nil {
		return nil, err
	}
	return e, nil
}
