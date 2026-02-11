package eval

import (
	"context"
	"io/fs"
	"os"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/zclconf/go-cty/cty"
)

func Eval(ctx context.Context, fsys fs.FS, root string, opts *EvalOpts) (*GraphEvaluator, error) {
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

	modResolver := NewModuleResolver(
		opts.Logger.With(log.Prefix("mod-resolver")),
		WithAllowDownloads(opts.AllowDownloads),
		WithSkipCachedModules(opts.SkipCachedModules),
	)

	rootMod, err := modResolver.Resolve(ctx, fsys, root)
	if err != nil {
		return nil, err
	}

	g := NewGraph()
	if err := g.Build(rootMod); err != nil {
		return nil, err
	}

	e := NewEvaluator(g, rootMod, opts)
	if err := e.EvalGraph(g); err != nil {
		return nil, err
	}
	return e, nil
}
