package types

import "github.com/aquasecurity/trivy-db/pkg/db"

type VersionInfo struct {
	Trivy           string      `json:",omitempty"`
	VulnerabilityDB db.Metadata `json:",omitempty"`
}

type Library struct {
	Name    string
	Version string
}
