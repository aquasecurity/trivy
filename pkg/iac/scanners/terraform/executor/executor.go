package executor

import (
	"runtime"
	"sort"
	"strings"
	"time"

	adapter "github.com/aquasecurity/trivy/pkg/iac/adapters/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/debug"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

// Executor scans HCL blocks by running all registered rules against them
type Executor struct {
	enableIgnores             bool
	excludedRuleIDs           []string
	excludeIgnoresIDs         []string
	includedRuleIDs           []string
	ignoreCheckErrors         bool
	workspaceName             string
	useSingleThread           bool
	debug                     debug.Logger
	resultsFilters            []func(scan.Results) scan.Results
	alternativeIDProviderFunc func(string) []string
	severityOverrides         map[string]string
	regoScanner               *rego.Scanner
	regoOnly                  bool
	stateFuncs                []func(*state.State)
	frameworks                []framework.Framework
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
		regoOnly:          false,
	}
	for _, option := range options {
		option(s)
	}
	return s
}

// Find element in list
func checkInList(id string, altIDs, list []string) bool {
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

func (e *Executor) Execute(modules terraform.Modules) (scan.Results, Metrics, error) {

	var metrics Metrics

	e.debug.Log("Adapting modules...")
	adaptationTime := time.Now()
	infra := adapter.Adapt(modules)
	metrics.Timings.Adaptation = time.Since(adaptationTime)
	e.debug.Log("Adapted %d module(s) into defsec state data.", len(modules))

	threads := runtime.NumCPU()
	if threads > 1 {
		threads--
	}
	if e.useSingleThread {
		threads = 1
	}
	e.debug.Log("Using max routines of %d", threads)

	e.debug.Log("Applying state modifier functions...")
	for _, f := range e.stateFuncs {
		f(infra)
	}

	checksTime := time.Now()
	registeredRules := rules.GetRegistered(e.frameworks...)
	e.debug.Log("Initialized %d rule(s).", len(registeredRules))

	pool := NewPool(threads, registeredRules, modules, infra, e.ignoreCheckErrors, e.regoScanner, e.regoOnly)
	e.debug.Log("Created pool with %d worker(s) to apply rules.", threads)
	results, err := pool.Run()
	if err != nil {
		return nil, metrics, err
	}
	metrics.Timings.RunningChecks = time.Since(checksTime)
	e.debug.Log("Finished applying rules.")

	if e.enableIgnores {
		e.debug.Log("Applying ignores...")
		var ignores terraform.Ignores
		for _, module := range modules {
			ignores = append(ignores, module.Ignores()...)
		}

		ignores = e.removeExcludedIgnores(ignores)

		for i, result := range results {
			allIDs := []string{
				result.Rule().LongID(),
				result.Rule().AVDID,
				strings.ToLower(result.Rule().AVDID),
				result.Rule().ShortCode,
			}
			allIDs = append(allIDs, result.Rule().Aliases...)

			if e.alternativeIDProviderFunc != nil {
				allIDs = append(allIDs, e.alternativeIDProviderFunc(result.Rule().LongID())...)
			}
			if ignores.Covering(
				modules,
				result.Metadata(),
				e.workspaceName,
				allIDs...,
			) != nil {
				e.debug.Log("Ignored '%s' at '%s'.", result.Rule().LongID(), result.Range())
				results[i].OverrideStatus(scan.StatusIgnored)
			}
		}
	} else {
		e.debug.Log("Ignores are disabled.")
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

func (e *Executor) removeExcludedIgnores(ignores terraform.Ignores) terraform.Ignores {
	var filteredIgnores terraform.Ignores
	for _, ignore := range ignores {
		if !contains(e.excludeIgnoresIDs, ignore.RuleID) {
			filteredIgnores = append(filteredIgnores, ignore)
		}
	}
	return filteredIgnores
}

func contains(arr []string, s string) bool {
	for _, elem := range arr {
		if elem == s {
			return true
		}
	}
	return false
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

func (e *Executor) filterResults(results scan.Results) scan.Results {
	includedOnly := len(e.includedRuleIDs) > 0
	for i, result := range results {
		id := result.Rule().LongID()
		var altIDs []string
		if e.alternativeIDProviderFunc != nil {
			altIDs = e.alternativeIDProviderFunc(id)
		}
		if (includedOnly && !checkInList(id, altIDs, e.includedRuleIDs)) || checkInList(id, altIDs, e.excludedRuleIDs) {
			e.debug.Log("Excluding '%s' at '%s'.", result.Rule().LongID(), result.Range())
			results[i].OverrideStatus(scan.StatusIgnored)
		}
	}

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
