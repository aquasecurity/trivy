package terraform

import (
	"io/fs"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/executor"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

type ConfigurableTerraformScanner interface {
	options.ConfigurableScanner
	SetForceAllDirs(bool)
	AddExecutorOptions(options ...executor.Option)
	AddParserOptions(options ...options.ParserOption)
}

func ScannerWithTFVarsPaths(paths ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddParserOptions(parser.OptionWithTFVarsPaths(paths...))
		}
	}
}

func ScannerWithAlternativeIDProvider(f func(string) []string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddExecutorOptions(executor.OptionWithAlternativeIDProvider(f))
		}
	}
}

func ScannerWithSeverityOverrides(overrides map[string]string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddExecutorOptions(executor.OptionWithSeverityOverrides(overrides))
		}
	}
}

func ScannerWithNoIgnores() options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddExecutorOptions(executor.OptionNoIgnores())
		}
	}
}

func ScannerWithExcludedRules(ruleIDs []string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddExecutorOptions(executor.OptionExcludeRules(ruleIDs))
		}
	}
}

func ScannerWithExcludeIgnores(ruleIDs []string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddExecutorOptions(executor.OptionExcludeIgnores(ruleIDs))
		}
	}
}

func ScannerWithIncludedRules(ruleIDs []string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddExecutorOptions(executor.OptionIncludeRules(ruleIDs))
		}
	}
}

func ScannerWithStopOnRuleErrors(stop bool) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddExecutorOptions(executor.OptionStopOnErrors(stop))
		}
	}
}

func ScannerWithWorkspaceName(name string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddParserOptions(parser.OptionWithWorkspaceName(name))
			tf.AddExecutorOptions(executor.OptionWithWorkspaceName(name))
		}
	}
}

func ScannerWithSingleThread(single bool) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddExecutorOptions(executor.OptionWithSingleThread(single))
		}
	}
}

func ScannerWithAllDirectories(all bool) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.SetForceAllDirs(all)
		}
	}
}

func ScannerWithStopOnHCLError(stop bool) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddParserOptions(parser.OptionStopOnHCLError(stop))
		}
	}
}

func ScannerWithSkipDownloaded(skip bool) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if !skip {
			return
		}
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddExecutorOptions(executor.OptionWithResultsFilter(func(results scan.Results) scan.Results {
				for i, result := range results {
					prefix := result.Range().GetSourcePrefix()
					switch {
					case prefix == "":
					case strings.HasPrefix(prefix, "."):
					default:
						results[i].OverrideStatus(scan.StatusIgnored)
					}
				}
				return results
			}))
		}
	}
}

func ScannerWithResultsFilter(f func(scan.Results) scan.Results) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddExecutorOptions(executor.OptionWithResultsFilter(f))
		}
	}
}

func ScannerWithMinimumSeverity(minimum severity.Severity) options.ScannerOption {
	min := severityAsOrdinal(minimum)
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddExecutorOptions(executor.OptionWithResultsFilter(func(results scan.Results) scan.Results {
				for i, result := range results {
					if severityAsOrdinal(result.Severity()) < min {
						results[i].OverrideStatus(scan.StatusIgnored)
					}
				}
				return results
			}))
		}
	}
}

func severityAsOrdinal(sev severity.Severity) int {
	switch sev {
	case severity.Critical:
		return 4
	case severity.High:
		return 3
	case severity.Medium:
		return 2
	case severity.Low:
		return 1
	default:
		return 0
	}
}

func ScannerWithStateFunc(f ...func(*state.State)) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddExecutorOptions(executor.OptionWithStateFunc(f...))
		}
	}
}

func ScannerWithDownloadsAllowed(allowed bool) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddParserOptions(parser.OptionWithDownloads(allowed))
		}
	}
}

func ScannerWithSkipCachedModules(b bool) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddParserOptions(parser.OptionWithSkipCachedModules(b))
		}
	}
}

func ScannerWithConfigsFileSystem(fsys fs.FS) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddParserOptions(parser.OptionWithConfigsFS(fsys))
		}
	}
}
