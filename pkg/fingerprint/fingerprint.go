package fingerprint

import (
	"fmt"

	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Fill generates and fills fingerprints for all findings in the report
func Fill(report *types.Report) {
	artifactID := report.ArtifactID

	for i := range report.Results {
		result := &report.Results[i]
		target := result.Target

		// Fill vulnerability fingerprints
		fillVulnerabilities(artifactID, target, result.Vulnerabilities)

		// TODO: Future implementation
		// fillMisconfigurations(artifactID, target, result.Misconfigurations)
		// fillSecrets(artifactID, target, result.Secrets)
		// fillLicenses(artifactID, target, result.Licenses)
	}
}

// fillVulnerabilities generates and assigns fingerprints to all vulnerabilities in the slice.
// Each vulnerability is processed in place to ensure the fingerprint is added to the original
// vulnerability object in the report.
func fillVulnerabilities(artifactID, target string, vulns []types.DetectedVulnerability) {
	for i := range vulns {
		vulns[i].Fingerprint = generateVulnFingerprint(artifactID, target, &vulns[i])
	}
}

// generateVulnFingerprint creates a unique fingerprint for a vulnerability.
// The fingerprint is a SHA256 hash of the concatenation of:
//   - artifactID: Unique identifier for the scanned artifact (e.g., image digest with registry/repository)
//   - target: Scan target path (e.g., "app/package.json" or "alpine 3.18.0")
//   - PkgID: Package identifier with version (e.g., "lodash@4.17.0" or "libssl3@3.0.8-r0")
//   - VulnerabilityID: CVE or vulnerability identifier (e.g., "CVE-2021-1234")
//
// The fingerprint is deterministic - the same inputs always produce the same hash.
// This allows external systems to track and deduplicate vulnerabilities across multiple scans.
//
// Example: For a vulnerability in lodash@4.17.0 found in app/package.json of sha256:abc123,
// the fingerprint would be SHA256("sha256:abc123:app/package.json:lodash@4.17.0:CVE-2021-1234")
// resulting in "sha256:..." format.
func generateVulnFingerprint(artifactID, target string, vuln *types.DetectedVulnerability) string {
	data := fmt.Sprintf("%s:%s:%s:%s",
		artifactID,
		target,
		vuln.PkgID,
		vuln.VulnerabilityID)
	return digest.CalcSHA256([]byte(data)).String()
}

// fillMisconfigurations will generate and assign fingerprints to all misconfigurations.
// TODO: Implement when misconfiguration fingerprints are needed.
// The implementation should follow the same pattern as fillVulnerabilities,
// creating deterministic fingerprints based on artifactID, target, and misconfiguration-specific identifiers.
//
//nolint:unused // Placeholder for future implementation
func fillMisconfigurations(_, _ string, _ []types.DetectedMisconfiguration) {
	// Future implementation
	// for i := range misconfs {
	//     misconfs[i].Fingerprint = generateMisconfigFingerprint(artifactID, target, &misconfs[i])
	// }
}

// fillSecrets will generate and assign fingerprints to all detected secrets.
// TODO: Implement when secret fingerprints are needed.
// The implementation should follow the same pattern as fillVulnerabilities,
// creating deterministic fingerprints based on artifactID, target, and secret-specific identifiers.
//
//nolint:unused // Placeholder for future implementation
func fillSecrets(_, _ string, _ []types.DetectedSecret) {
	// Future implementation
	// for i := range secrets {
	//     secrets[i].Fingerprint = generateSecretFingerprint(artifactID, target, &secrets[i])
	// }
}

// fillLicenses will generate and assign fingerprints to all detected licenses.
// TODO: Implement when license fingerprints are needed.
// The implementation should follow the same pattern as fillVulnerabilities,
// creating deterministic fingerprints based on artifactID, target, and license-specific identifiers.
//
//nolint:unused // Placeholder for future implementation
func fillLicenses(_, _ string, _ []types.DetectedLicense) {
	// Future implementation
	// for i := range licenses {
	//     licenses[i].Fingerprint = generateLicenseFingerprint(artifactID, target, &licenses[i])
	// }
}
