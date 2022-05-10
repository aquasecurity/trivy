package executor

import (
	"io"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/pkg/config"
)

type Option func(s *Executor)

func OptionWithConfig(c config.Config) func(s *Executor) {
	return func(s *Executor) {
		s.config = c
	}
}

func OptionWithResultsFilter(f func(rules.Results) rules.Results) Option {
	return func(s *Executor) {
		s.resultsFilters = append(s.resultsFilters, f)
	}
}

func OptionWithDebugWriter(w io.Writer) Option {
	return func(s *Executor) {
		s.debugWriter = w
	}
}

func OptionIncludePassed(include bool) func(s *Executor) {
	return func(s *Executor) {
		s.includePassed = include
	}
}

func OptionIncludeIgnored(include bool) func(s *Executor) {
	return func(s *Executor) {
		s.includeIgnored = include
	}
}

func OptionExcludeRules(ruleIDs []string) func(s *Executor) {
	return func(s *Executor) {
		s.excludedRuleIDs = ruleIDs
	}
}

func OptionIncludeRules(ruleIDs []string) func(s *Executor) {
	return func(s *Executor) {
		s.includedRuleIDs = ruleIDs
	}
}

func OptionStopOnErrors(stop bool) func(s *Executor) {
	return func(s *Executor) {
		s.ignoreCheckErrors = !stop
	}
}

func OptionWithWorkspaceName(workspaceName string) func(s *Executor) {
	return func(s *Executor) {
		s.workspaceName = workspaceName
	}
}

func OptionWithSingleThread(single bool) func(s *Executor) {
	return func(s *Executor) {
		s.useSingleThread = single
	}
}
