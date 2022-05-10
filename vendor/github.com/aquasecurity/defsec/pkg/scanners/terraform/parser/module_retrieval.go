package parser

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/aquasecurity/defsec/pkg/scanners/terraform/parser/resolvers"
)

type ModuleResolver interface {
	Resolve(context.Context, fs.FS, resolvers.Options) (filesystem fs.FS, prefix string, downloadPath string, applies bool, err error)
}

var defaultResolvers = []ModuleResolver{
	resolvers.Cache,
	resolvers.Local,
	resolvers.Remote,
	resolvers.Registry,
}

func resolveModule(ctx context.Context, current fs.FS, opt resolvers.Options) (filesystem fs.FS, sourcePrefix string, downloadPath string, err error) {
	opt.Debug("Resolving module '%s' with source: '%s'...", opt.Name, opt.Source)
	for _, resolver := range defaultResolvers {
		if filesystem, prefix, path, applies, err := resolver.Resolve(ctx, current, opt); err != nil {
			return nil, "", "", err
		} else if applies {
			opt.Debug("Module path is %s", path)
			return filesystem, prefix, path, nil
		}
	}
	return nil, "", "", fmt.Errorf("failed to resolve module '%s' with source: %s", opt.Name, opt.Source)
}
