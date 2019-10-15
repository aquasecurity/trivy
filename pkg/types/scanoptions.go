package types

import "time"

type ScanOptions struct {
	VulnType []string
	Timeout  time.Duration
}
