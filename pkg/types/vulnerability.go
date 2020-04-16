package types

import (
	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

type DetectedVulnerability struct {
	VulnerabilityID  string       `json:",omitempty"`
	PkgName          string       `json:",omitempty"`
	InstalledVersion string       `json:",omitempty"`
	FixedVersion     string       `json:",omitempty"`
	Layer            ftypes.Layer `json:",omitempty"`
	SeveritySource   string       `json:",omitempty"`

	types.Vulnerability
}
