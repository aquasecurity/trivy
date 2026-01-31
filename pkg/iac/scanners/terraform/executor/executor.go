package executor

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
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
	scanRawConfig  bool
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

	e.logger.Debug("Scan state data")
	results, err := e.regoScanner.ScanInput(ctx, types.SourceCloud, rego.Input{
		Contents: infra.ToRego(),
		Path:     basePath,
	})
	if err != nil {
		return nil, err
	}

	if e.scanRawConfig {
		e.logger.Debug("Scan raw Terraform data")
		results2, err := e.regoScanner.ScanInput(ctx, types.SourceTerraformRaw, rego.Input{
			Contents: terraform.ExportModules(modules),
			Path:     basePath,
		})
		if err != nil {
			e.logger.Error("Failed to scan raw Terraform data",
				log.FilePath(basePath), log.Err(err))
		} else {
			results = append(results, results2...)
		}
	}

	e.logger.Debug("Finished applying checks")

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
			log.String("rule", ignored.Rule().CanonicalID()),
			log.String("range", ignored.Range().String()),
		)
	}

	results = e.filterResults(results)

	for i, res := range results {
		if res.Status() != scan.StatusFailed {
			continue
		}

		res.WithRenderedCause(e.renderCause(modules, res.Range()))
		results[i] = res
	}

	return results, nil
}

func (e *Executor) renderCause(modules terraform.Modules, causeRng types.Range) scan.RenderedCause {
	tfBlock := findBlockForCause(modules, causeRng)
	if tfBlock == nil {
		e.logger.Debug("No matching Terraform block found", log.String("cause_range", causeRng.String()))
		return scan.RenderedCause{}
	}

	block := hclwrite.NewBlock(tfBlock.Type(), normalizeBlockLables(tfBlock))

	if !writeBlock(tfBlock, block, causeRng) {
		e.logger.Debug("No matching block attribute found", log.String("cause_range", causeRng.String()))
		return scan.RenderedCause{}
	}

	f := hclwrite.NewEmptyFile()
	f.Body().AppendBlock(block)

	cause := string(hclwrite.Format(f.Bytes()))
	cause = strings.TrimSuffix(cause, "\n")
	return scan.RenderedCause{Raw: cause}
}

// normalizeBlockLables removes indexes and keys from labels.
func normalizeBlockLables(block *terraform.Block) []string {
	labels := block.Labels()
	if block.IsExpanded() {
		nameLabel := labels[len(labels)-1]
		idx := strings.LastIndex(nameLabel, "[")
		if idx != -1 {
			labels[len(labels)-1] = nameLabel[:idx]
		}
	}

	return labels
}

func writeBlock(tfBlock *terraform.Block, block *hclwrite.Block, causeRng types.Range) bool {
	var found bool

	for _, attr := range tfBlock.Attributes() {
		if !attr.GetMetadata().Range().Covers(causeRng) || attr.IsLiteral() {
			continue
		}

		value := attr.Value()
		if !value.IsWhollyKnown() {
			continue
		}

		block.Body().SetAttributeValue(attr.Name(), value)
		found = true
	}

	for _, child := range tfBlock.AllBlocks() {
		if child.GetMetadata().Range().Covers(causeRng) {
			childBlock := hclwrite.NewBlock(child.Type(), nil)
			if writeBlock(child, childBlock, causeRng) {
				block.Body().AppendBlock(childBlock)
				found = true
			}
		}
	}

	return found
}

func findBlockForCause(modules terraform.Modules, causeRng types.Range) *terraform.Block {
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
		if val.IsNull() || !val.IsKnown() {
			return false
		}
		switch val.Type() {
		case cty.String:
			if val.AsString() != param {
				return false
			}
		case cty.Number:
			bf := val.AsBigFloat()
			f64, _ := bf.Float64()
			comparableInt := strconv.Itoa(int(f64))
			comparableFloat := fmt.Sprintf("%f", f64)
			if param != comparableInt && param != comparableFloat {
				return false
			}
		case cty.Bool:
			if strconv.FormatBool(val.True()) != param {
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
