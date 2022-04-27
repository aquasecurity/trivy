package parser

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/defsec/parsers/terraform/parser/resolvers"
)

type ModuleResolver interface {
	Resolve(context.Context, resolvers.Options) (downloadPath string, applies bool, err error)
}

var defaultResolvers = []ModuleResolver{
	resolvers.Cache,
	resolvers.Local,
	resolvers.Remote,
	resolvers.Registry,
}

func resolveModule(ctx context.Context, opt resolvers.Options) (downloadPath string, err error) {
	opt.Debug("Resolving module '%s' with source: '%s'...", opt.Name, opt.Source)
	for _, resolver := range defaultResolvers {
		if path, applies, err := resolver.Resolve(ctx, opt); err != nil {
			return "", err
		} else if applies {
			return cleanPath(opt.ModulePath, path), nil
		}
	}
	return "", fmt.Errorf("failed to resolve module '%s' with source: %s", opt.Name, opt.Source)
}

func cleanPath(modulePath, path string) string {
	if strings.HasPrefix(path, fmt.Sprintf(".%c", os.PathSeparator)) ||
		strings.HasPrefix(path, fmt.Sprintf("..%c", os.PathSeparator)) {
		path = filepath.Join(modulePath, path)
	}
	return path
}
