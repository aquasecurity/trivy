package parser

import (
	"io/fs"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/trivy/pkg/log"
)

type Option func(p *Parser)

func OptionWithTFVarsPaths(paths ...string) Option {
	return func(p *Parser) {
		p.tfvarsPaths = paths
	}
}

func OptionStopOnHCLError(stop bool) Option {
	return func(p *Parser) {
		p.stopOnHCLError = stop
	}
}

func OptionWithLogger(log *log.Logger) Option {
	return func(p *Parser) {
		p.logger = log
	}
}

func OptionWithWorkingDirectoryPath(cwd string) Option {
	return func(p *Parser) {
		p.cwd = cwd
	}
}

func OptionsWithTfVars(vars map[string]cty.Value) Option {
	return func(p *Parser) {
		p.tfvars = vars
	}
}

func OptionWithWorkspaceName(workspaceName string) Option {
	return func(p *Parser) {
		p.workspaceName = workspaceName
	}
}

func OptionWithDownloads(allowed bool) Option {
	return func(p *Parser) {
		p.allowDownloads = allowed
	}
}

func OptionWithSkipCachedModules(b bool) Option {
	return func(p *Parser) {
		p.skipCachedModules = b
	}
}

func OptionWithConfigsFS(fsys fs.FS) Option {
	return func(p *Parser) {
		p.configsFS = fsys
	}
}

func OptionWithSkipFiles(files []string) Option {
	return func(p *Parser) {
		p.skipPaths = files
	}
}

func OptionWithSkipDirs(dirs []string) Option {
	return func(p *Parser) {
		p.skipPaths = dirs
	}
}
