package options

type ConfigurableScanner any

type ScannerOption func(s ConfigurableScanner)

type RawConfigScanner interface {
	SetScanRawConfig(v bool)
}

func WithScanRawConfig(v bool) ScannerOption {
	return func(s ConfigurableScanner) {
		if ss, ok := s.(RawConfigScanner); ok {
			ss.SetScanRawConfig(v)
		}
	}
}
