package types

type FindingType string
type FindingStatus string

const (
	FindingTypeVulnerability    FindingType = "vulnerability"
	FindingTypeMisconfiguration FindingType = "misconfiguration"
	FindingTypeSecret           FindingType = "secret"
	FindingTypeLicense          FindingType = "license"

	FindingStatusIgnored            FindingStatus = "ignored"             // Trivy
	FindingStatusUnknown            FindingStatus = "unknown"             // Trivy
	FindingStatusNotAffected        FindingStatus = "not_affected"        // VEX
	FindingStatusAffected           FindingStatus = "affected"            // VEX
	FindingStatusFixed              FindingStatus = "fixed"               // VEX
	FindingStatusUnderInvestigation FindingStatus = "under_investigation" // VEX
)

// Finding represents one of the findings that Trivy can detect,
// such as vulnerabilities, misconfigurations, secrets, and licenses.
type finding interface {
	findingType() FindingType
}

// ModifiedFinding represents a security finding that has been modified by an external source,
// such as .trivyignore and VEX. Currently, it is primarily used to account for vulnerabilities
// that are ignored via .trivyignore or identified as not impactful through VEX.
// However, it is planned to also store vulnerabilities whose severity has been adjusted by VEX,
// or that have been detected through Wasm modules in the future.
type ModifiedFinding struct {
	Type      FindingType
	Status    FindingStatus
	Statement string
	Source    string
	Finding   finding // one of findings
}

func NewModifiedFinding(f finding, status FindingStatus, statement, source string) ModifiedFinding {
	return ModifiedFinding{
		Type:      f.findingType(),
		Status:    status,
		Statement: statement,
		Source:    source,
		Finding:   f,
	}
}
