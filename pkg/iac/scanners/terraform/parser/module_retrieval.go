package parser

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser/resolvers"
	"github.com/aquasecurity/trivy/pkg/log"
)

type ModuleResolver interface {
	Resolve(context.Context, fs.FS, resolvers.Options) (filesystem fs.FS, prefix string, downloadPath string, applies bool, err error)
}

var defaultResolvers = []ModuleResolver{
	resolvers.Local,
	resolvers.Cache,
	resolvers.Remote,
	resolvers.Registry,
}

func resolveModule(ctx context.Context, current fs.FS, opt resolvers.Options) (filesystem fs.FS, sourcePrefix, downloadPath string, err error) {
	opt.Logger.Debug("Resolving module",
		log.String("name", opt.Name), log.String("source", opt.Source))
	for _, resolver := range defaultResolvers {
		if filesystem, prefix, path, applies, err := resolver.Resolve(ctx, current, opt); err != nil {
			return nil, "", "", err
		} else if applies {
			opt.Logger.Debug("Module resolved", log.FilePath(path))
			return filesystem, prefix, path, nil
		}
	}
	return nil, "", "", fmt.Errorf("failed to resolve module '%s' with source: %s", opt.Name, opt.Source)
}
