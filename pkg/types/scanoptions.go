package types

type ScanOptions struct {
	VulnType []string

	// for client/server
	RemoteURL string
	Token     string
}
