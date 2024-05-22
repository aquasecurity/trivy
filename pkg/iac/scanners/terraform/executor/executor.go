package executor

import (
	"fmt"
	"runtime"
	"sort"

	"github.com/zclconf/go-cty/cty"

	adapter "github.com/aquasecurity/trivy/pkg/iac/adapters/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/debug"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/ignore"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

// Executor scans HCL blocks by running all registered rules against them
type Executor struct {
	workspaceName  string
	debug          debug.Logger
	resultsFilters []func(scan.Results) scan.Results
	regoScanner    *rego.Scanner
	regoOnly       bool
	frameworks     []framework.Framework
}

// New creates a new Executor
func New(options ...Option) *Executor {
	s := &Executor{
		regoOnly: false,
	}
	for _, option := range options {
		option(s)
	}
	return s
}

func (e *Executor) Execute(modules terraform.Modules) (scan.Results, error) {

	e.debug.Log("Adapting modules...")
	infra := adapter.Adapt(modules)
	e.debug.Log("Adapted %d module(s) into defsec state data.", len(modules))

	threads := runtime.NumCPU()
	if threads > 1 {
		threads--
	}

	e.debug.Log("Using max routines of %d", threads)

	registeredRules := rules.GetRegistered(e.frameworks...)
	e.debug.Log("Initialized %d rule(s).", len(registeredRules))

	pool := NewPool(threads, registeredRules, modules, infra, e.regoScanner, e.regoOnly)
	e.debug.Log("Created pool with %d worker(s) to apply rules.", threads)

	results, err := pool.Run()
	if err != nil {
		return nil, err
	}

	e.debug.Log("Finished applying rules.")

	e.debug.Log("Applying ignores...")
	var ignores ignore.Rules
	for _, module := range modules {
		ignores = append(ignores, module.Ignores()...)
	}

	ignorers := map[string]ignore.Ignorer{
		"ws":     workspaceIgnorer(e.workspaceName),
		"ignore": attributeIgnorer(modules),
	}

	results.Ignore(ignores, ignorers)

	for _, ignored := range results.GetIgnored() {
		e.debug.Log("Ignored '%s' at '%s'.", ignored.Rule().LongID(), ignored.Range())
	}

	results = e.filterResults(results)

	e.sortResults(results)
	return results, nil
}

func (e *Executor) filterResults(results scan.Results) scan.Results {
	if len(e.resultsFilters) > 0 && len(results) > 0 {
		before := len(results.GetIgnored())
		e.debug.Log("Applying %d results filters to %d results...", len(results), before)
		for _, filter := range e.resultsFilters {
			results = filter(results)
		}
		e.debug.Log("Filtered out %d results.", len(results.GetIgnored())-before)
	}

	return results
}

func (e *Executor) sortResults(results []scan.Result) {
	sort.Slice(results, func(i, j int) bool {
		switch {
		case results[i].Rule().LongID() < results[j].Rule().LongID():
			return true
		case results[i].Rule().LongID() > results[j].Rule().LongID():
			return false
		default:
			return results[i].Range().String() > results[j].Range().String()
		}
	})
}

func ignoreByParams(params map[string]string, modules terraform.Modules, m *types.Metadata) bool {
	if len(params) == 0 {
		return true
	}
	block := modules.GetBlockByIgnoreRange(m)
	if block == nil {
		return true
	}
	for key, val := range params {
		attr, _ := block.GetNestedAttribute(key)
		if attr.IsNil() || !attr.Value().IsKnown() {
			return false
		}
		switch attr.Type() {
		case cty.String:
			if !attr.Equals(val) {
				return false
			}
		case cty.Number:
			bf := attr.Value().AsBigFloat()
			f64, _ := bf.Float64()
			comparableInt := fmt.Sprintf("%d", int(f64))
			comparableFloat := fmt.Sprintf("%f", f64)
			if val != comparableInt && val != comparableFloat {
				return false
			}
		case cty.Bool:
			if fmt.Sprintf("%t", attr.IsTrue()) != val {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func workspaceIgnorer(ws string) ignore.Ignorer {
	return func(_ types.Metadata, param any) bool {
		ignoredWorkspace, ok := param.(string)
		if !ok {
			return false
		}
		return ignore.MatchPattern(ws, ignoredWorkspace)
	}
}

func attributeIgnorer(modules terraform.Modules) ignore.Ignorer {
	return func(resultMeta types.Metadata, param any) bool {
		params, ok := param.(map[string]string)
		if !ok {
			return false
		}
		return ignoreByParams(params, modules, &resultMeta)
	}
}
