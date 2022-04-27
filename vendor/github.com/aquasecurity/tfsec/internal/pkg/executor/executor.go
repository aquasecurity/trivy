package executor

import (
	"fmt"
	"io"
	"io/ioutil"
	"runtime"
	"sort"
	"time"

	"github.com/aquasecurity/tfsec/internal/pkg/config"

	"github.com/aquasecurity/defsec/severity"

	adapter "github.com/aquasecurity/defsec/adapters/terraform"
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/pkg/legacy"
)

// Executor scans HCL blocks by running all registered rules against them
type Executor struct {
	includePassed     bool
	includeIgnored    bool
	excludedRuleIDs   []string
	includedRuleIDs   []string
	ignoreCheckErrors bool
	workspaceName     string
	useSingleThread   bool
	debugWriter       io.Writer
	resultsFilters    []func(rules.Results) rules.Results
	config            config.Config
}

type Metrics struct {
	Timings struct {
		Adaptation    time.Duration
		RunningChecks time.Duration
	}
	Counts struct {
		Ignored  int
		Excluded int
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
		debugWriter:       ioutil.Discard,
	}
	for _, option := range options {
		option(s)
	}
	return s
}

// Find element in list
func checkInList(id string, legacyID string, list []string) bool {
	for _, codeIgnored := range list {
		if codeIgnored == id || (legacyID != "" && codeIgnored == legacyID) {
			return true
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

func (e *Executor) Execute(modules terraform.Modules) (rules.Results, Metrics, error) {

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

	checksTime := time.Now()
	registeredRules := GetRegisteredRules()
	e.debug("Initialised %d rule(s).", len(registeredRules))
	pool := NewPool(threads, registeredRules, modules, infra, e.ignoreCheckErrors)
	e.debug("Created pool with %d worker(s) to apply rules.", threads)
	results, err := pool.Run()
	if err != nil {
		return nil, metrics, err
	}
	metrics.Timings.RunningChecks = time.Since(checksTime)
	e.debug("Finished applying rules.")

	var resultsAfterIgnores []rules.Result
	if !e.includeIgnored {
		var ignores terraform.Ignores
		for _, module := range modules {
			ignores = append(ignores, module.Ignores()...)
		}

		for _, result := range results {
			if !e.includeIgnored && ignores.Covering(
				modules,
				result.Metadata(),
				e.workspaceName,
				result.Rule().LongID(),
				legacy.FindID(result.Rule().LongID()),
				result.Rule().AVDID,
			) != nil {
				e.debug("Ignored '%s' at '%s'.", result.Rule().LongID(), result.Range())
				continue
			}
			resultsAfterIgnores = append(resultsAfterIgnores, result)
		}
	} else {
		resultsAfterIgnores = results
	}

	metrics.Counts.Ignored = len(results) - len(resultsAfterIgnores)

	filtered, excludeCount := e.filterResults(resultsAfterIgnores)
	metrics.Counts.Excluded = excludeCount

	filtered = e.updateSeverity(filtered)

	for _, res := range filtered {
		if res.Status() == rules.StatusPassed {
			metrics.Counts.Passed++
		} else {
			metrics.Counts.Failed++
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
	}

	e.sortResults(filtered)
	return filtered, metrics, nil
}

func (e *Executor) updateSeverity(results []rules.Result) []rules.Result {
	overrides := e.config.SeverityOverrides
	if len(overrides) == 0 {
		return results
	}

	var overriddenResults []rules.Result
	for _, res := range results {
		for code, sev := range overrides {
			if res.Rule().LongID() == code || legacy.FindID(res.Rule().LongID()) == code {
				overrides := rules.Results([]rules.Result{res})
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

func (e *Executor) filterResults(results []rules.Result) ([]rules.Result, int) {
	var filtered []rules.Result
	var countExcluded int

	// nolint // deliberate action of appending to a different slice
	includedList := append(e.includedRuleIDs, e.config.IncludedChecks...)
	// nolint // deliberate action of appending to a different slice
	excludedList := append(e.excludedRuleIDs, e.config.ExcludedChecks...)
	includedOnly := len(includedList) > 0

	for _, result := range results {
		id := result.Rule().LongID()
		legacyID := legacy.FindID(id)
		if !includedOnly || checkInList(id, legacyID, includedList) {
			if !e.includeIgnored && checkInList(id, legacyID, excludedList) {
				e.debug("Excluding '%s' at '%s'.", result.Rule().LongID(), result.Range())
				countExcluded++
			} else if e.includePassed || result.Status() != rules.StatusPassed {
				filtered = append(filtered, result)
			}
		}
	}
	for _, filter := range e.resultsFilters {
		filtered = filter(filtered)
	}
	return filtered, countExcluded
}

func (e *Executor) sortResults(results []rules.Result) {
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
