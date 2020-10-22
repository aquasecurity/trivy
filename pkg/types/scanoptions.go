package types

// ScanOptions holds the attributes for scanning vulnerabilities
type ScanOptions struct {
	VulnType            []string
	ScanRemovedPackages bool
	ListAllPackages     bool
	SkipFiles           []string
	SkipDirectories     []string
}
