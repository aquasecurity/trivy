# Deterministic CISA-KEV Triage Policy for Trivy

A dual-signal evaluation module that prioritizes actively weaponized CISA Known Exploited Vulnerabilities (KEV) and suppresses theoretical scanner noise in container and lockfile scans.

## Overview

Container and SBOM scans frequently report hundreds of un-prioritized CVE findings, blocking CI/CD pipelines on packages without active exploitation.

This module introduces a deterministic Gate/Prove evaluation standard:
1. **`never_equate_scan_to_exploit: true`**: Differentiates between verified active KEV threats (`fix_now`) and passive version banner matches (`accept` / `transfer`).
2. **Deterministic Triage Dispositions**:
   - `fix_now`: Actively exploited CISA-KEV vulnerability or high-severity flaw with available patch.
   - `accept`: Theoretical vulnerability or dev-dependency without active exploitability.
   - `escalate`: Critical/High vulnerability with no upstream fix requiring mitigation.
3. **Structured Audit Receipts**: Generates SHA-256 hash-verified decision records for SOC 2 Type II and ISO 27001 compliance evidence.

## Running Tests

```bash
go test -v ./contrib/triage
```

## License

Apache-2.0
