package executor

import (
	"fmt"
	"io"
	"io/ioutil"
	"runtime"
	"sort"
	"time"

	"github.com/aquasecurity/defsec/pkg/terraform"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/rules"

	"github.com/aquasecurity/defsec/pkg/rego"

	adapter "github.com/aquasecurity/defsec/internal/adapters/terraform"
)

// Executor scans HCL blocks by running all registered rules against them
type Executor struct {
	enableIgnores             bool
	excludedRuleIDs           []string
	includedRuleIDs           []string
	ignoreCheckErrors         bool
	workspaceName             string
	useSingleThread           bool
	debugWriter               io.Writer
	resultsFilters            []func(scan.Results) scan.Results
	alternativeIDProviderFunc func(string) []string
	severityOverrides         map[string]string
	regoScanner               *rego.Scanner
	regoOnly                  bool
	stateFuncs                []func(*state.State)
}

type Metrics struct {
	Timings struct {
		Adaptation    time.Duration
		RunningChecks time.Duration
	}
	Counts struct {
		Ignored  int
		Failed   int
		Passed   int
		Critical int
		High     int
		Medium   int
		Low      int
	}
}

// New creates a new Executor
func New(options ...Option) *Executor {
	s := &Executor{
		ignoreCheckErrors: true,
		enableIgnores:     true,
		debugWriter:       ioutil.Discard,
		regoOnly:          false,
	}
	for _, option := range options {
		option(s)
	}
	return s
}

// Find element in list
func checkInList(id string, altIDs []string, list []string) bool {
	for _, codeIgnored := range list {
		if codeIgnored == id {
			return true
		}
		for _, alt := range altIDs {
			if alt == codeIgnored {
				return true
			}
		}
	}
	return false
}

func (e *Executor) debug(format string, args ...interface{}) {
	if e.debugWriter == nil {
		return
	}
	prefix := "[debug:exec] "
	_, _ = e.debugWriter.Write([]byte(fmt.Sprintf(prefix+format+"\n", args...)))
}

func (e *Executor) Execute(modules terraform.Modules) (scan.Results, Metrics, error) {

	var metrics Metrics

	adaptationTime := time.Now()
	infra := adapter.Adapt(modules)
	metrics.Timings.Adaptation = time.Since(adaptationTime)
	e.debug("Adapted %d module(s) into defsec state data.", len(modules))

	threads := runtime.NumCPU()
	if threads > 1 {
		threads--
	}
	if e.useSingleThread {
		threads = 1
	}

	for _, f := range e.stateFuncs {
		f(infra)
	}

	checksTime := time.Now()
	registeredRules := rules.GetRegistered()
	e.debug("Initialised %d rule(s).", len(registeredRules))

	pool := NewPool(threads, registeredRules, modules, infra, e.ignoreCheckErrors, e.regoScanner, e.regoOnly)
	e.debug("Created pool with %d worker(s) to apply rules.", threads)
	results, err := pool.Run()
	if err != nil {
		return nil, metrics, err
	}
	metrics.Timings.RunningChecks = time.Since(checksTime)
	e.debug("Finished applying rules.")

	if e.enableIgnores {
		var ignores terraform.Ignores
		for _, module := range modules {
			ignores = append(ignores, module.Ignores()...)
		}

		for i, result := range results {
			allIDs := []string{
				result.Rule().LongID(),
				result.Rule().AVDID,
			}
			if e.alternativeIDProviderFunc != nil {
				allIDs = append(allIDs, e.alternativeIDProviderFunc(result.Rule().LongID())...)
			}
			if ignores.Covering(
				modules,
				result.Metadata(),
				e.workspaceName,
				allIDs...,
			) != nil {
				e.debug("Ignored '%s' at '%s'.", result.Rule().LongID(), result.Range())
				results[i].OverrideStatus(scan.StatusIgnored)
			}
		}
	}

	results = e.updateSeverity(results)
	results = e.filterResults(results)
	metrics.Counts.Ignored = len(results.GetIgnored())
	metrics.Counts.Passed = len(results.GetPassed())
	metrics.Counts.Failed = len(results.GetFailed())

	for _, res := range results.GetFailed() {
		switch res.Severity() {
		case severity.Critical:
			metrics.Counts.Critical++
		case severity.High:
			metrics.Counts.High++
		case severity.Medium:
			metrics.Counts.Medium++
		case severity.Low:
			metrics.Counts.Low++
		}
	}

	e.sortResults(results)
	return results, metrics, nil
}

func (e *Executor) updateSeverity(results []scan.Result) scan.Results {
	if len(e.severityOverrides) == 0 {
		return results
	}

	var overriddenResults scan.Results
	for _, res := range results {
		for code, sev := range e.severityOverrides {

			var altMatch bool
			if e.alternativeIDProviderFunc != nil {
				alts := e.alternativeIDProviderFunc(res.Rule().LongID())
				for _, alt := range alts {
					if alt == code {
						altMatch = true
						break
					}
				}
			}

			if altMatch || res.Rule().LongID() == code {
				overrides := scan.Results([]scan.Result{res})
				override := res.Rule()
				override.Severity = severity.Severity(sev)
				overrides.SetRule(override)
				res = overrides[0]
			}
		}
		overriddenResults = append(overriddenResults, res)
	}

	return overriddenResults
}

func (e *Executor) filterResults(results []scan.Result) scan.Results {
	includedOnly := len(e.includedRuleIDs) > 0
	for i, result := range results {
		id := result.Rule().LongID()
		var altIDs []string
		if e.alternativeIDProviderFunc != nil {
			altIDs = e.alternativeIDProviderFunc(id)
		}
		if (includedOnly && !checkInList(id, altIDs, e.includedRuleIDs)) || checkInList(id, altIDs, e.excludedRuleIDs) {
			e.debug("Excluding '%s' at '%s'.", result.Rule().LongID(), result.Range())
			results[i].OverrideStatus(scan.StatusIgnored)
		}
	}

	for _, filter := range e.resultsFilters {
		results = filter(results)
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
