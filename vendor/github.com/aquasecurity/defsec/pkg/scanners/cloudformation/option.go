package cloudformation

import (
	"github.com/aquasecurity/defsec/pkg/scanners/options"
)

type ConfigurableCloudFormationScanner interface {
	options.ConfigurableScanner
	SetRegoOnly(regoOnly bool)
}

func ScannerWithRegoOnly(regoOnly bool) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableCloudFormationScanner); ok {
			tf.SetRegoOnly(regoOnly)
		}
	}
}
