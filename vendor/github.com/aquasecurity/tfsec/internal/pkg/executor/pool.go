package executor

import (
	"fmt"
	runtimeDebug "runtime/debug"
	"sync"

	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

type Pool struct {
	size         int
	modules      terraform.Modules
	state        *state.State
	rules        []rule.Rule
	ignoreErrors bool
}

func NewPool(size int, rules []rule.Rule, modules terraform.Modules, state *state.State, ignoreErrors bool) *Pool {
	return &Pool{
		size:         size,
		rules:        rules,
		state:        state,
		modules:      modules,
		ignoreErrors: ignoreErrors,
	}
}

// Run runs the job in the pool - this will only return an error if a job panics
func (p *Pool) Run() (rules.Results, error) {

	outgoing := make(chan Job, p.size*2)

	var workers []*Worker
	for i := 0; i < p.size; i++ {
		worker := NewWorker(outgoing)
		go worker.Start()
		workers = append(workers, worker)
	}

	for _, r := range p.rules {
		if r.CheckTerraform != nil {
			// run local hcl rule
			for _, module := range p.modules {
				outgoing <- &hclModuleRuleJob{
					module:       module,
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

	close(outgoing)

	var results rules.Results
	for _, worker := range workers {
		results = append(results, worker.Wait()...)
		if err := worker.Error(); err != nil {
			return nil, err
		}
	}

	return results, nil
}

type Job interface {
	Run() (rules.Results, error)
}

type infraRuleJob struct {
	state *state.State
	rule  rule.Rule

	ignoreErrors bool
}

type hclModuleRuleJob struct {
	module       *terraform.Module
	rule         rule.Rule
	ignoreErrors bool
}

func (h *infraRuleJob) Run() (_ rules.Results, err error) {
	if h.ignoreErrors {
		defer func() {
			if panicErr := recover(); panicErr != nil {
				err = fmt.Errorf("%s\n%s", panicErr, string(runtimeDebug.Stack()))
			}
		}()
	}
	return h.rule.CheckAgainstState(h.state), err
}

func (h *hclModuleRuleJob) Run() (results rules.Results, err error) {
	if h.ignoreErrors {
		defer func() {
			if panicErr := recover(); panicErr != nil {
				err = fmt.Errorf("%s\n%s", panicErr, string(runtimeDebug.Stack()))
			}
		}()
	}
	for _, block := range h.module.GetBlocks() {
		results = append(results, h.rule.CheckAgainstBlock(block, h.module)...)
	}
	return
}

type Worker struct {
	incoming <-chan Job
	mu       sync.Mutex
	results  rules.Results
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

func (w *Worker) Wait() rules.Results {
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
