package parser

import (
	"context"
	"fmt"
	"io/fs"

	resolvers2 "github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser/resolvers"
)

type ModuleResolver interface {
	Resolve(context.Context, fs.FS, resolvers2.Options) (filesystem fs.FS, prefix string, downloadPath string, applies bool, err error)
}

var defaultResolvers = []ModuleResolver{
	resolvers2.Cache,
	resolvers2.Local,
	resolvers2.Remote,
	resolvers2.Registry,
}

func resolveModule(ctx context.Context, current fs.FS, opt resolvers2.Options) (filesystem fs.FS, sourcePrefix, downloadPath string, err error) {
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
