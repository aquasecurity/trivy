package triage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// TriageDisposition represents the operational decision for a vulnerability.
type TriageDisposition string

const (
	DispositionFixNow   TriageDisposition = "fix_now"
	DispositionAccept   TriageDisposition = "accept"
	DispositionTransfer TriageDisposition = "transfer"
	DispositionEscalate TriageDisposition = "escalate"
)

// DecisionRecord captures the deterministic triage evaluation for an alert.
type DecisionRecord struct {
	VulnID                   string            `json:"vuln_id"`
	PkgName                  string            `json:"pkg_name"`
	InstalledVersion         string            `json:"installed_version"`
	FixedVersion             string            `json:"fixed_version,omitempty"`
	Severity                 string            `json:"severity"`
	CisaKevActive            bool              `json:"cisa_kev_active"`
	TriageDisposition        TriageDisposition `json:"triage_disposition"`
	NeverEquateScanToExploit bool              `json:"never_equate_scan_to_exploit"`
	Reason                   string            `json:"reason"`
	ReceiptHash              string            `json:"receipt_hash"`
	Timestamp                string            `json:"timestamp"`
	ComplianceMapping        []string          `json:"compliance_mapping"`
}

// Evaluator evaluates vulnerability findings under deterministic dual-signal policy.
type Evaluator struct {
	knownKevMap map[string]bool
}

// NewEvaluator creates a new vulnerability triage evaluator.
func NewEvaluator(kevList []string) *Evaluator {
	kmap := make(map[string]bool)
	for _, k := range kevList {
		kmap[strings.ToUpper(strings.TrimSpace(k))] = true
	}
	return &Evaluator{knownKevMap: kmap}
}

// Evaluate evaluates a vulnerability finding into a DecisionRecord.
func (e *Evaluator) Evaluate(vulnID, pkgName, installedVersion, fixedVersion, severity string, isDevDep bool) DecisionRecord {
	vulnUpper := strings.ToUpper(strings.TrimSpace(vulnID))
	isKev := e.knownKevMap[vulnUpper]

	var disp TriageDisposition
	var reason string

	if isKev {
		disp = DispositionFixNow
		reason = "cisa_kev_active_exploit_verified"
	} else if isDevDep {
		disp = DispositionAccept
		reason = "dev_dependency_theoretical_risk"
	} else if strings.EqualFold(severity, "CRITICAL") || strings.EqualFold(severity, "HIGH") {
		if fixedVersion != "" {
			disp = DispositionFixNow
			reason = "high_severity_patch_available"
		} else {
			disp = DispositionEscalate
			reason = "high_severity_no_upstream_fix"
		}
	} else {
		disp = DispositionAccept
		reason = "low_impact_routine_backlog"
	}

	ts := time.Now().UTC().Format(time.RFC3339)
	payload := vulnUpper + ":" + pkgName + ":" + installedVersion + ":" + string(disp) + ":" + ts
	hash := sha256.Sum256([]byte(payload))
	receiptHash := hex.EncodeToString(hash[:])

	return DecisionRecord{
		VulnID:                   vulnID,
		PkgName:                  pkgName,
		InstalledVersion:         installedVersion,
		FixedVersion:             fixedVersion,
		Severity:                 severity,
		CisaKevActive:            isKev,
		TriageDisposition:        disp,
		NeverEquateScanToExploit: true,
		Reason:                   reason,
		ReceiptHash:              receiptHash,
		Timestamp:                ts,
		ComplianceMapping:        []string{"SOC2_CC7.1", "ISO_27001_A.12.6.1", "NIST_CSF_ID.RA"},
	}
}

// ToJSON marshals decision records into formatted JSON.
func (d *DecisionRecord) ToJSON() (string, error) {
	bytes, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
