package executor

import (
	"fmt"
	"runtime"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/samber/lo"
	"github.com/zclconf/go-cty/cty"

	adapter "github.com/aquasecurity/trivy/pkg/iac/adapters/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/ignore"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	ruleTypes "github.com/aquasecurity/trivy/pkg/iac/types/rules"
	"github.com/aquasecurity/trivy/pkg/log"
)

// Executor scans HCL blocks by running all registered rules against them
type Executor struct {
	workspaceName           string
	logger                  *log.Logger
	resultsFilters          []func(scan.Results) scan.Results
	regoScanner             *rego.Scanner
	regoOnly                bool
	includeDeprecatedChecks bool
	frameworks              []framework.Framework
}

// New creates a new Executor
func New(options ...Option) *Executor {
	s := &Executor{
		regoOnly: false,
		logger:   log.WithPrefix("terraform executor"),
	}
	for _, option := range options {
		option(s)
	}
	return s
}

func (e *Executor) Execute(modules terraform.Modules) (scan.Results, error) {

	e.logger.Debug("Adapting modules...")
	infra := adapter.Adapt(modules)
	e.logger.Debug("Adapted module(s) into state data.", log.Int("count", len(modules)))

	threads := runtime.NumCPU()
	if threads > 1 {
		threads--
	}

	e.logger.Debug("Using max routines", log.Int("count", threads))

	registeredRules := lo.Filter(rules.GetRegistered(e.frameworks...), func(r ruleTypes.RegisteredRule, _ int) bool {
		if !e.includeDeprecatedChecks && r.Deprecated {
			return false // skip deprecated checks
		}

		return true
	})
	e.logger.Debug("Initialized Go check(s).", log.Int("count", len(registeredRules)))

	pool := NewPool(threads, registeredRules, modules, infra, e.regoScanner, e.regoOnly)

	results, err := pool.Run()
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
	for i, res := range results {
		if res.Status() != scan.StatusFailed {
			continue
		}

		res.WithRenderedCause(renderCause(modules, res.Range()))
		results[i] = res
	}

	return results, nil
}

func renderCause(modules terraform.Modules, causeRng types.Range) scan.RenderedCause {
	tfBlock := findBlockByRange(modules, causeRng)
	if tfBlock == nil {
		return scan.RenderedCause{}
	}

	f := hclwrite.NewEmptyFile()
	block := f.Body().AppendNewBlock(tfBlock.Type(), tfBlock.Labels())

	if !writeBlock(tfBlock, block, causeRng) {
		return scan.RenderedCause{}
	}

	cause := string(hclwrite.Format(f.Bytes()))
	cause = strings.TrimSuffix(string(cause), "\n")
	highlighted, _ := scan.Highlight(causeRng.GetFilename(), cause, scan.DarkTheme)
	return scan.RenderedCause{
		Raw:         cause,
		Highlighted: highlighted,
	}
}

func writeBlock(tfBlock *terraform.Block, block *hclwrite.Block, causeRng types.Range) bool {
	var found bool
	for _, attr := range tfBlock.Attributes() {
		if !attr.GetMetadata().Range().Covers(causeRng) || attr.IsLiteral() {
			continue
		}
		found = true
		block.Body().SetAttributeValue(attr.Name(), attr.Value())
	}

	for _, childTfBlock := range tfBlock.AllBlocks() {
		if !childTfBlock.GetMetadata().Range().Covers(causeRng) {
			continue
		}
		childBlock := hclwrite.NewBlock(childTfBlock.Type(), nil)

		attrFound := writeBlock(childTfBlock, childBlock, causeRng)
		if attrFound {
			block.Body().AppendBlock(childBlock)
		}
		found = found || attrFound
	}

	return found
}

func findBlockByRange(modules terraform.Modules, causeRng types.Range) *terraform.Block {
	for _, block := range modules.GetBlocks() {
		blockRng := block.GetMetadata().Range()
		if blockRng.GetFilename() == causeRng.GetFilename() && blockRng.Includes(causeRng) {
			return block
		}
	}
	return nil
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
