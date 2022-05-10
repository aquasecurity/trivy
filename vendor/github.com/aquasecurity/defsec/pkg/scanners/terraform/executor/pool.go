package executor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	runtimeDebug "runtime/debug"
	"strings"
	"sync"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/terraform"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	rules3 "github.com/aquasecurity/defsec/internal/rules"

	"github.com/aquasecurity/defsec/pkg/rego"
)

type Pool struct {
	size         int
	modules      terraform.Modules
	state        *state.State
	rules        []rules3.RegisteredRule
	ignoreErrors bool
	rs           *rego.Scanner
	regoOnly     bool
}

func NewPool(size int, rules []rules3.RegisteredRule, modules terraform.Modules, state *state.State, ignoreErrors bool, regoScanner *rego.Scanner, regoOnly bool) *Pool {
	return &Pool{
		size:         size,
		rules:        rules,
		state:        state,
		modules:      modules,
		ignoreErrors: ignoreErrors,
		rs:           regoScanner,
		regoOnly:     regoOnly,
	}
}

// Run runs the job in the pool - this will only return an error if a job panics
func (p *Pool) Run() (scan.Results, error) {

	outgoing := make(chan Job, p.size*2)

	var workers []*Worker
	for i := 0; i < p.size; i++ {
		worker := NewWorker(outgoing)
		go worker.Start()
		workers = append(workers, worker)
	}

	if p.rs != nil {
		var basePath string
		if len(p.modules) > 0 {
			basePath = p.modules[0].RootPath()
		}
		outgoing <- &regoJob{
			state:    p.state,
			scanner:  p.rs,
			basePath: basePath,
		}
	}

	if !p.regoOnly {
		for _, r := range p.rules {
			if r.Rule().CustomChecks.Terraform != nil && r.Rule().CustomChecks.Terraform.Check != nil {
				// run local hcl rule
				for _, module := range p.modules {
					mod := *module
					outgoing <- &hclModuleRuleJob{
						module:       &mod,
						rule:         r,
						ignoreErrors: p.ignoreErrors,
					}
				}
			} else {
				// run defsec rule
				outgoing <- &infraRuleJob{
					state:        p.state,
					rule:         r,
					ignoreErrors: p.ignoreErrors,
				}
			}
		}
	}

	close(outgoing)

	var results scan.Results
	for _, worker := range workers {
		results = append(results, worker.Wait()...)
		if err := worker.Error(); err != nil {
			return nil, err
		}
	}

	return results, nil
}

type Job interface {
	Run() (scan.Results, error)
}

type infraRuleJob struct {
	state *state.State
	rule  rules3.RegisteredRule

	ignoreErrors bool
}

type hclModuleRuleJob struct {
	module       *terraform.Module
	rule         rules3.RegisteredRule
	ignoreErrors bool
}

type regoJob struct {
	state    *state.State
	scanner  *rego.Scanner
	basePath string
}

func (h *infraRuleJob) Run() (_ scan.Results, err error) {
	if h.ignoreErrors {
		defer func() {
			if panicErr := recover(); panicErr != nil {
				err = fmt.Errorf("%s\n%s", panicErr, string(runtimeDebug.Stack()))
			}
		}()
	}
	return h.rule.Evaluate(h.state), err
}

func (h *hclModuleRuleJob) Run() (results scan.Results, err error) {
	if h.ignoreErrors {
		defer func() {
			if panicErr := recover(); panicErr != nil {
				err = fmt.Errorf("%s\n%s", panicErr, string(runtimeDebug.Stack()))
			}
		}()
	}
	customCheck := h.rule.Rule().CustomChecks.Terraform
	for _, block := range h.module.GetBlocks() {
		if !isCustomCheckRequiredForBlock(customCheck, block) {
			continue
		}
		results = append(results, customCheck.Check(block, h.module)...)
	}
	results.SetRule(h.rule.Rule())
	return
}

func (h *regoJob) Run() (results scan.Results, err error) {
	regoResults, err := h.scanner.ScanInput(context.TODO(), rego.Input{
		Contents: h.state.ToRego(),
		Type:     types.SourceDefsec,
		Path:     h.basePath,
	})
	if err != nil {
		return nil, fmt.Errorf("rego scan error: %w", err)
	}
	return regoResults, nil
}

func isCustomCheckRequiredForBlock(custom *scan.TerraformCustomCheck, b *terraform.Block) bool {

	var found bool
	for _, requiredType := range custom.RequiredTypes {
		if b.Type() == requiredType {
			found = true
			break
		}
	}
	if !found && len(custom.RequiredTypes) > 0 {
		return false
	}

	found = false
	for _, requiredLabel := range custom.RequiredLabels {
		if requiredLabel == "*" || (len(b.Labels()) > 0 && wildcardMatch(requiredLabel, b.TypeLabel())) {
			found = true
			break
		}
	}
	if !found && len(custom.RequiredLabels) > 0 {
		return false
	}

	found = false
	if len(custom.RequiredSources) > 0 && b.Type() == terraform.TypeModule.Name() {
		if sourceAttr := b.GetAttribute("source"); sourceAttr.IsNotNil() {
			sourcePath := sourceAttr.ValueAsStrings()[0]

			// resolve module source path to path relative to cwd
			if strings.HasPrefix(sourcePath, ".") {
				sourcePath = cleanPathRelativeToWorkingDir(filepath.Dir(b.GetMetadata().Range().GetFilename()), sourcePath)
			}

			for _, requiredSource := range custom.RequiredSources {
				if requiredSource == "*" || wildcardMatch(requiredSource, sourcePath) {
					found = true
					break
				}
			}
		}
		return found
	}

	return true
}

func cleanPathRelativeToWorkingDir(dir, path string) string {
	absPath := filepath.Clean(filepath.Join(dir, path))
	wDir, err := os.Getwd()
	if err != nil {
		return absPath
	}
	relPath, err := filepath.Rel(wDir, absPath)
	if err != nil {
		return absPath
	}
	return relPath
}

func wildcardMatch(pattern string, subject string) bool {
	if pattern == "" {
		return false
	}
	parts := strings.Split(pattern, "*")
	var lastIndex int
	for i, part := range parts {
		if part == "" {
			continue
		}
		if i == 0 {
			if !strings.HasPrefix(subject, part) {
				return false
			}
		}
		if i == len(parts)-1 {
			if !strings.HasSuffix(subject, part) {
				return false
			}
		}
		newIndex := strings.Index(subject, part)
		if newIndex < lastIndex {
			return false
		}
		lastIndex = newIndex
	}
	return true
}

type Worker struct {
	incoming <-chan Job
	mu       sync.Mutex
	results  scan.Results
	panic    interface{}
}

func NewWorker(incoming <-chan Job) *Worker {
	w := &Worker{
		incoming: incoming,
	}
	w.mu.Lock()
	return w
}

func (w *Worker) Start() {
	defer w.mu.Unlock()
	w.results = nil
	for job := range w.incoming {
		func() {
			results, err := job.Run()
			if err != nil {
				w.panic = err
			}
			w.results = append(w.results, results...)
		}()
	}
}

func (w *Worker) Wait() scan.Results {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.results
}

func (w *Worker) Error() error {
	if w.panic == nil {
		return nil
	}
	return fmt.Errorf("job failed: %s", w.panic)
}
