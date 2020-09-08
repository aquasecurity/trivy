package types

type ScanOptions struct {
	VulnType            []string
	ScanRemovedPackages bool
	ListAllPackages     bool
	SkipFiles           []string
	SkipDirectories     []string
}
