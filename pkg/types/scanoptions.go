package types

import "time"

type ScanOptions struct {
	VulnType   []string
	SkipUpdate bool
	Timeout    time.Duration
}
