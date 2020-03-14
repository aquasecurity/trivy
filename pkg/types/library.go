package types

import "github.com/aquasecurity/trivy-db/pkg/db"

type VersionInfo struct {
	TrivyVersion           string      `json:",omitempty"`
	VulnerabilityDBVersion db.Metadata `json:",omitempty"`
}

type Library struct {
	Name    string
	Version string
}
