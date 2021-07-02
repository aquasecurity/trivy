package types

// ScanOptions holds the attributes for scanning vulnerabilities
type ScanOptions struct {
	VulnType            []string
	SecurityChecks      []string
	SkipFiles           []string
	SkipDirs            []string
	ScanRemovedPackages bool
	ListAllPackages     bool
	AnalyzeOnly         bool
}
