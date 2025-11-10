package terraform

import (
	"io/fs"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/executor"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
)

type ConfigurableTerraformScanner interface {
	options.ConfigurableScanner
	SetForceAllDirs(bool)
	AddExecutorOptions(options ...executor.Option)
	AddParserOptions(options ...parser.Option)
}

func ScannerWithTFVarsPaths(paths ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddParserOptions(parser.OptionWithTFVarsPaths(paths...))
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

func ScannerWithAllDirectories(all bool) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.SetForceAllDirs(all)
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
					if prefix != "" && !strings.HasPrefix(prefix, ".") {
						results[i].OverrideStatus(scan.StatusIgnored)
					}
				}
				return results
			}))
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

func ScannerWithSkipFiles(files []string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddParserOptions(parser.OptionWithSkipFiles(files))
		}
	}
}

func ScannerWithSkipDirs(dirs []string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddParserOptions(parser.OptionWithSkipDirs(dirs))
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
