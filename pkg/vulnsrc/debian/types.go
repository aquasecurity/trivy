package debian

import "github.com/knqyf263/trivy/pkg/vulnsrc/nvd"

type DebianCVE struct {
	Description     string             `json:"description"`
	Releases        map[string]Release `json:"releases"`
	Scope           string             `json:"scope"`
	Package         string
	VulnerabilityID string
}

type Release struct {
	Repositories map[string]string `json:"repositories"`
	Status       string            `json:"status"`
	Urgency      string            `json:"urgency"`
}

type Advisory struct {
	VulnerabilityID string
	Severity        nvd.Severity
}
