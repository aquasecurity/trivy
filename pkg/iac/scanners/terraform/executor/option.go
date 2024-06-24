package executor

import (
	"io"

	"github.com/aquasecurity/trivy/pkg/iac/debug"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
)

type Option func(s *Executor)

func OptionWithFrameworks(frameworks ...framework.Framework) Option {
	return func(s *Executor) {
		s.frameworks = frameworks
	}
}

func OptionWithResultsFilter(f func(scan.Results) scan.Results) Option {
	return func(s *Executor) {
		s.resultsFilters = append(s.resultsFilters, f)
	}
}

func OptionWithDebugWriter(w io.Writer) Option {
	return func(s *Executor) {
		s.debug = debug.New(w, "terraform", "executor")
	}
}

func OptionWithWorkspaceName(workspaceName string) Option {
	return func(s *Executor) {
		s.workspaceName = workspaceName
	}
}

func OptionWithRegoScanner(s *rego.Scanner) Option {
	return func(e *Executor) {
		e.regoScanner = s
	}
}

func OptionWithRegoOnly(regoOnly bool) Option {
	return func(e *Executor) {
		e.regoOnly = regoOnly
	}
}
