package scanner

import (
	"github.com/aquasecurity/fanal/utils"
	"github.com/tfsec/tfsec/pkg/severity"
)

var criticalRuleIDs = []string{
	"AWS004",
	"AWS011",
	"AWS013",
	"AWS044",
	"AWS046",
	"AWS049",
	"AWS062",
	"AWS069",
	"AZU010",
	"AZU017",
	"AZU024",
	"GEN001",
	"GEN002",
	"GEN003",
}

func severityFromTFSec(ruleID string, sev severity.Severity) string {
	// workaround until tfsec reclassifies severities
	if utils.StringInSlice(ruleID, criticalRuleIDs) {
		return "CRITICAL"
	}

	switch sev {
	case severity.Info:
		return "LOW"
	case severity.Warning:
		return "MEDIUM"
	case severity.Error:
		return "HIGH"
	case severity.Critical:
		return "CRITICAL"
	}
	return "UNKNOWN"
}
