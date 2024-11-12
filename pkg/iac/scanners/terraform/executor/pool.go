package executor

import (
	"context"
	"fmt"
	"sync"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

type Pool struct {
	size    int
	modules terraform.Modules
	state   *state.State
	rs      *rego.Scanner
}

func NewPool(size int, modules terraform.Modules, st *state.State, regoScanner *rego.Scanner) *Pool {
	return &Pool{
		size:    size,
		state:   st,
		modules: modules,
		rs:      regoScanner,
	}
}

// Run runs the job in the pool - this will only return an error if a job panics
func (p *Pool) Run() (scan.Results, error) {

	outgoing := make(chan *regoJob, p.size*2)

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

type regoJob struct {
	state    *state.State
	scanner  *rego.Scanner
	basePath string
}

func (h *regoJob) Run() (results scan.Results, err error) {
	regoResults, err := h.scanner.ScanInput(context.TODO(), rego.Input{
		Contents: h.state.ToRego(),
		Path:     h.basePath,
	})
	if err != nil {
		return nil, fmt.Errorf("rego scan error: %w", err)
	}
	return regoResults, nil
}

type Worker struct {
	incoming <-chan *regoJob
	mu       sync.Mutex
	results  scan.Results
	panic    any
}

func NewWorker(incoming <-chan *regoJob) *Worker {
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
