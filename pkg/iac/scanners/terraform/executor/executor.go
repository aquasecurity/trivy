package executor

import (
	"context"
	"fmt"
	"sort"

	"github.com/zclconf/go-cty/cty"

	adapter "github.com/aquasecurity/trivy/pkg/iac/adapters/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/ignore"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

// Executor scans HCL blocks by running all registered rules against them
type Executor struct {
	workspaceName  string
	logger         *log.Logger
	resultsFilters []func(scan.Results) scan.Results
	regoScanner    *rego.Scanner
}

// New creates a new Executor
func New(options ...Option) *Executor {
	s := &Executor{
		logger: log.WithPrefix("terraform executor"),
	}
	for _, option := range options {
		option(s)
	}
	return s
}

func (e *Executor) Execute(ctx context.Context, modules terraform.Modules, basePath string) (scan.Results, error) {

	e.logger.Debug("Adapting modules...")
	infra := adapter.Adapt(modules)
	e.logger.Debug("Adapted module(s) into state data.", log.Int("count", len(modules)))

	results, err := e.regoScanner.ScanInput(ctx, rego.Input{
		Contents: infra.ToRego(),
		Path:     basePath,
	})
	if err != nil {
		return nil, err
	}

	e.logger.Debug("Finished applying rules.")

	e.logger.Debug("Applying ignores...")
	var ignores ignore.Rules
	for _, module := range modules {
		ignores = append(ignores, module.Ignores()...)
	}

	ignorers := map[string]ignore.Ignorer{
		"ws":     workspaceIgnorer(e.workspaceName),
		"ignore": attributeIgnorer(modules),
	}

	// ignore a result based on user input
	results.Ignore(ignores, ignorers)

	for _, ignored := range results.GetIgnored() {
		e.logger.Info("Ignore finding",
			log.String("rule", ignored.Rule().LongID()),
			log.String("range", ignored.Range().String()),
		)
	}

	results = e.filterResults(results)

	e.sortResults(results)
	return results, nil
}

func (e *Executor) filterResults(results scan.Results) scan.Results {
	if len(e.resultsFilters) > 0 && len(results) > 0 {
		before := len(results.GetIgnored())
		e.logger.Debug("Applying results filters...")
		for _, filter := range e.resultsFilters {
			results = filter(results)
		}
		e.logger.Debug("Applied results filters.",
			log.Int("count", len(results.GetIgnored())-before))
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
	for key, param := range params {
		val := block.GetValueByPath(key)
		switch val.Type() {
		case cty.String:
			if val.AsString() != param {
				return false
			}
		case cty.Number:
			bf := val.AsBigFloat()
			f64, _ := bf.Float64()
			comparableInt := fmt.Sprintf("%d", int(f64))
			comparableFloat := fmt.Sprintf("%f", f64)
			if param != comparableInt && param != comparableFloat {
				return false
			}
		case cty.Bool:
			if fmt.Sprintf("%t", val.True()) != param {
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
