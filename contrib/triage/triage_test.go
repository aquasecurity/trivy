package triage

import (
	"testing"
)

func TestTriageEvaluator(t *testing.T) {
	evaluator := NewEvaluator([]string{"CVE-2023-38606", "CVE-2021-44228"})

	// 1. KEV Active -> fix_now
	r1 := evaluator.Evaluate("CVE-2021-44228", "log4j-core", "2.14.0", "2.17.1", "CRITICAL", false)
	if r1.TriageDisposition != DispositionFixNow {
		t.Errorf("expected fix_now, got %s", r1.TriageDisposition)
	}
	if !r1.CisaKevActive {
		t.Errorf("expected cisa_kev_active true")
	}
	if !r1.NeverEquateScanToExploit {
		t.Errorf("expected never_equate_scan_to_exploit true")
	}

	// 2. Dev dependency -> accept
	r2 := evaluator.Evaluate("CVE-2020-12345", "mocha", "1.0.0", "1.0.1", "MEDIUM", true)
	if r2.TriageDisposition != DispositionAccept {
		t.Errorf("expected accept for dev dep, got %s", r2.TriageDisposition)
	}

	// 3. Receipt hash generated
	if len(r1.ReceiptHash) != 64 {
		t.Errorf("expected 64 char sha256 hash, got %s", r1.ReceiptHash)
	}
}
