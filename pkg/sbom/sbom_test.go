package sbom_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/sbom"
)

// Test data constants for SBOM format detection and decoding.
// Each constant contains base64-encoded in-toto statement in the payload field.
const (
	// SPDX attestation (DSSE envelope)
	// payload decoded: {"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://spdx.dev/Document","subject":[{"name":"test","digest":{"sha256":"abc123"}}],"predicate":{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3","name":"test","dataLicense":"CC0-1.0","documentNamespace":"http://example.invalid/test","creationInfo":{"creators":["Tool: test"],"created":"2025-01-01T00:00:00Z"},"packages":[]}}
	spdxAttestation = `{
		"payloadType": "application/vnd.in-toto+json",
		"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3NwZHguZGV2L0RvY3VtZW50Iiwic3ViamVjdCI6W3sibmFtZSI6InRlc3QiLCJkaWdlc3QiOnsic2hhMjU2IjoiYWJjMTIzIn19XSwicHJlZGljYXRlIjp7IlNQRFhJRCI6IlNQRFhSZWYtRE9DVU1FTlQiLCJzcGR4VmVyc2lvbiI6IlNQRFgtMi4zIiwibmFtZSI6InRlc3QiLCJkYXRhTGljZW5zZSI6IkNDMC0xLjAiLCJkb2N1bWVudE5hbWVzcGFjZSI6Imh0dHA6Ly9leGFtcGxlLmludmFsaWQvdGVzdCIsImNyZWF0aW9uSW5mbyI6eyJjcmVhdG9ycyI6WyJUb29sOiB0ZXN0Il0sImNyZWF0ZWQiOiIyMDI1LTAxLTAxVDAwOjAwOjAwWiJ9LCJwYWNrYWdlcyI6W119fQ==",
		"signatures": []
	}`

	// SPDX attestation with invalid SPDXID
	// payload decoded: {"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://spdx.dev/Document","subject":[{"name":"test","digest":{"sha256":"abc123"}}],"predicate":{"SPDXID":"InvalidID","spdxVersion":"SPDX-2.3","name":"test"}}
	spdxAttestationInvalidID = `{
		"payloadType": "application/vnd.in-toto+json",
		"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3NwZHguZGV2L0RvY3VtZW50Iiwic3ViamVjdCI6W3sibmFtZSI6InRlc3QiLCJkaWdlc3QiOnsic2hhMjU2IjoiYWJjMTIzIn19XSwicHJlZGljYXRlIjp7IlNQRFhJRCI6IkludmFsaWRJRCIsInNwZHhWZXJzaW9uIjoiU1BEWC0yLjMiLCJuYW1lIjoidGVzdCJ9fQ==",
		"signatures": []
	}`

	// SPDX attestation with invalid predicate (string instead of object)
	// payload decoded: {"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://spdx.dev/Document","subject":[{"name":"test","digest":{"sha256":"abc123"}}],"predicate":"invalid"}
	spdxAttestationInvalidPredicate = `{
		"payloadType": "application/vnd.in-toto+json",
		"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3NwZHguZGV2L0RvY3VtZW50Iiwic3ViamVjdCI6W3sibmFtZSI6InRlc3QiLCJkaWdlc3QiOnsic2hhMjU2IjoiYWJjMTIzIn19XSwicHJlZGljYXRlIjoiaW52YWxpZCJ9",
		"signatures": []
	}`

	// CycloneDX attestation (DSSE envelope)
	// payload decoded: {"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://cyclonedx.org/bom","subject":[{"name":"test","digest":{"sha256":"abc123"}}],"predicate":{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}}
	cycloneDXAttestation = `{
		"payloadType": "application/vnd.in-toto+json",
		"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL2N5Y2xvbmVkeC5vcmcvYm9tIiwic3ViamVjdCI6W3sibmFtZSI6InRlc3QiLCJkaWdlc3QiOnsic2hhMjU2IjoiYWJjMTIzIn19XSwicHJlZGljYXRlIjp7ImJvbUZvcm1hdCI6IkN5Y2xvbmVEWCIsInNwZWNWZXJzaW9uIjoiMS40IiwidmVyc2lvbiI6MX19",
		"signatures": []
	}`

	// Sigstore bundle with CycloneDX SBOM
	// dsseEnvelope.payload decoded: {"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://cyclonedx.org/bom","subject":[{"name":"test","digest":{"sha256":"abc123"}}],"predicate":{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}}
	sigstoreBundleCycloneDX = `{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"dsseEnvelope": {
			"payloadType": "application/vnd.in-toto+json",
			"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL2N5Y2xvbmVkeC5vcmcvYm9tIiwic3ViamVjdCI6W3sibmFtZSI6InRlc3QiLCJkaWdlc3QiOnsic2hhMjU2IjoiYWJjMTIzIn19XSwicHJlZGljYXRlIjp7ImJvbUZvcm1hdCI6IkN5Y2xvbmVEWCIsInNwZWNWZXJzaW9uIjoiMS40IiwidmVyc2lvbiI6MX19",
			"signatures": []
		}
	}`

	// Sigstore bundle with SPDX SBOM
	// dsseEnvelope.payload decoded: {"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://spdx.dev/Document","subject":[{"name":"test","digest":{"sha256":"abc123"}}],"predicate":{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3","name":"test","dataLicense":"CC0-1.0","documentNamespace":"http://example.invalid/test","creationInfo":{"creators":["Tool: test"],"created":"2025-01-01T00:00:00Z"},"packages":[]}}
	sigstoreBundleSPDX = `{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"dsseEnvelope": {
			"payloadType": "application/vnd.in-toto+json",
			"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3NwZHguZGV2L0RvY3VtZW50Iiwic3ViamVjdCI6W3sibmFtZSI6InRlc3QiLCJkaWdlc3QiOnsic2hhMjU2IjoiYWJjMTIzIn19XSwicHJlZGljYXRlIjp7IlNQRFhJRCI6IlNQRFhSZWYtRE9DVU1FTlQiLCJzcGR4VmVyc2lvbiI6IlNQRFgtMi4zIiwibmFtZSI6InRlc3QiLCJkYXRhTGljZW5zZSI6IkNDMC0xLjAiLCJkb2N1bWVudE5hbWVzcGFjZSI6Imh0dHA6Ly9leGFtcGxlLmludmFsaWQvdGVzdCIsImNyZWF0aW9uSW5mbyI6eyJjcmVhdG9ycyI6WyJUb29sOiB0ZXN0Il0sImNyZWF0ZWQiOiIyMDI1LTAxLTAxVDAwOjAwOjAwWiJ9LCJwYWNrYWdlcyI6W119fQ==",
			"signatures": []
		}
	}`

	// Sigstore bundle with unsupported media type version
	sigstoreBundleUnsupportedVersion = `{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.4+json",
		"dsseEnvelope": {
			"payloadType": "application/vnd.in-toto+json",
			"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL2N5Y2xvbmVkeC5vcmcvYm9tIiwic3ViamVjdCI6W3sibmFtZSI6InRlc3QiLCJkaWdlc3QiOnsic2hhMjU2IjoiYWJjMTIzIn19XSwicHJlZGljYXRlIjp7ImJvbUZvcm1hdCI6IkN5Y2xvbmVEWCIsInNwZWNWZXJzaW9uIjoiMS40IiwidmVyc2lvbiI6MX19",
			"signatures": []
		}
	}`
)

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  sbom.Format
	}{
		{
			name:  "SPDX attestation",
			input: spdxAttestation,
			want:  sbom.FormatAttestSPDXJSON,
		},
		{
			name:  "SPDX attestation with invalid SPDXID",
			input: spdxAttestationInvalidID,
			want:  sbom.FormatUnknown,
		},
		{
			name:  "CycloneDX attestation",
			input: cycloneDXAttestation,
			want:  sbom.FormatAttestCycloneDXJSON,
		},
		{
			name: "SPDX JSON",
			input: `{
				"SPDXID": "SPDXRef-DOCUMENT",
				"spdxVersion": "SPDX-2.3",
				"name": "test"
			}`,
			want: sbom.FormatSPDXJSON,
		},
		{
			name: "CycloneDX JSON",
			input: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.4"
			}`,
			want: sbom.FormatCycloneDXJSON,
		},
		{
			name: "Unknown format",
			input: `{
				"unknown": "format"
			}`,
			want: sbom.FormatUnknown,
		},
		{
			name:  "Sigstore bundle with CycloneDX",
			input: sigstoreBundleCycloneDX,
			want:  sbom.FormatSigstoreBundleCycloneDXJSON,
		},
		{
			name:  "Sigstore bundle with SPDX",
			input: sigstoreBundleSPDX,
			want:  sbom.FormatSigstoreBundleSPDXJSON,
		},
		{
			name:  "Sigstore bundle with unsupported version",
			input: sigstoreBundleUnsupportedVersion,
			want:  sbom.FormatUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.input)
			got, err := sbom.DetectFormat(r)

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDecode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		format  sbom.Format
		wantErr bool
	}{
		{
			name:    "SPDX attestation",
			input:   spdxAttestation,
			format:  sbom.FormatAttestSPDXJSON,
			wantErr: false,
		},
		{
			name:    "SPDX attestation with invalid predicate",
			input:   spdxAttestationInvalidPredicate,
			format:  sbom.FormatAttestSPDXJSON,
			wantErr: true,
		},
		{
			name:    "CycloneDX attestation",
			input:   cycloneDXAttestation,
			format:  sbom.FormatAttestCycloneDXJSON,
			wantErr: false,
		},
		{
			name:    "Sigstore bundle with CycloneDX",
			input:   sigstoreBundleCycloneDX,
			format:  sbom.FormatSigstoreBundleCycloneDXJSON,
			wantErr: false,
		},
		{
			name:    "Sigstore bundle with SPDX",
			input:   sigstoreBundleSPDX,
			format:  sbom.FormatSigstoreBundleSPDXJSON,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.input)
			_, err := sbom.Decode(t.Context(), r, tt.format)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestIsSPDXJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name: "Valid SPDX JSON",
			input: `{
				"SPDXID": "SPDXRef-DOCUMENT",
				"spdxVersion": "SPDX-2.3"
			}`,
			want: true,
		},
		{
			name: "Invalid SPDXID",
			input: `{
				"SPDXID": "InvalidID",
				"spdxVersion": "SPDX-2.3"
			}`,
			want: false,
		},
		{
			name: "Not SPDX",
			input: `{
				"bomFormat": "CycloneDX"
			}`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.input)
			got, err := sbom.IsSPDXJSON(r)

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsCycloneDXJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name: "Valid CycloneDX JSON",
			input: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.4"
			}`,
			want: true,
		},
		{
			name: "Not CycloneDX",
			input: `{
				"SPDXID": "SPDXRef-DOCUMENT"
			}`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.input)
			got, err := sbom.IsCycloneDXJSON(r)

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
