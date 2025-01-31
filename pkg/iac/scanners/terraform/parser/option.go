package parser

import (
	"io/fs"

	"github.com/zclconf/go-cty/cty"
)

type Option func(p *Parser)

func OptionWithEvalHook(hooks EvaluateStepHook) Option {
	return func(p *Parser) {
		p.stepHooks = append(p.stepHooks, hooks)
	}
}

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
