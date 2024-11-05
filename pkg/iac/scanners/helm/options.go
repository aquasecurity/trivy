package helm

import (
	"github.com/aquasecurity/trivy/pkg/iac/scanners/helm/parser"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
)

func ScannerWithValuesFile(paths ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if helmScanner, ok := s.(*Scanner); ok {
			helmScanner.addParserOptions(parser.OptionWithValuesFile(paths...))
		}
	}
}

func ScannerWithValues(values ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if helmScanner, ok := s.(*Scanner); ok {
			helmScanner.addParserOptions(parser.OptionWithValues(values...))
		}
	}
}

func ScannerWithFileValues(values ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if helmScanner, ok := s.(*Scanner); ok {
			helmScanner.addParserOptions(parser.OptionWithFileValues(values...))
		}
	}
}

func ScannerWithStringValues(values ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if helmScanner, ok := s.(*Scanner); ok {
			helmScanner.addParserOptions(parser.OptionWithStringValues(values...))
		}
	}
}

func ScannerWithAPIVersions(values ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if helmScanner, ok := s.(*Scanner); ok {
			helmScanner.addParserOptions(parser.OptionWithAPIVersions(values...))
		}
	}
}

func ScannerWithKubeVersion(values string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if helmScanner, ok := s.(*Scanner); ok {
			helmScanner.addParserOptions(parser.OptionWithKubeVersion(values))
		}
	}
}
