package sbom_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/sbom"
)

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  sbom.Format
	}{
		{
			name: "SPDX attestation with valid predicate",
			// DSSE envelope with base64-encoded in-toto statement
			input: `{
				"payloadType": "application/vnd.in-toto+json",
				"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3NwZHguZGV2L0RvY3VtZW50Iiwic3ViamVjdCI6W3sibmFtZSI6InRlc3QiLCJkaWdlc3QiOnsic2hhMjU2IjoiYWJjMTIzIn19XSwicHJlZGljYXRlIjp7IlNQRFhJRCI6IlNQRFhSZWYtRE9DVU1FTlQiLCJzcGR4VmVyc2lvbiI6IlNQRFgtMi4zIiwibmFtZSI6InRlc3QifX0=",
				"signatures": []
			}`,
			want: sbom.FormatAttestSPDXJSON,
		},
		{
			name: "SPDX attestation without SPDXID prefix",
			// Base64-encoded: {"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://spdx.dev/Document","subject":[{"name":"test","digest":{"sha256":"abc123"}}],"predicate":{"SPDXID":"InvalidID","spdxVersion":"SPDX-2.3","name":"test"}}
			input: `{
				"payloadType": "application/vnd.in-toto+json",
				"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3NwZHguZGV2L0RvY3VtZW50Iiwic3ViamVjdCI6W3sibmFtZSI6InRlc3QiLCJkaWdlc3QiOnsic2hhMjU2IjoiYWJjMTIzIn19XSwicHJlZGljYXRlIjp7IlNQRFhJRCI6IkludmFsaWRJRCIsInNwZHhWZXJzaW9uIjoiU1BEWC0yLjMiLCJuYW1lIjoidGVzdCJ9fQ==",
				"signatures": []
			}`,
			want: sbom.FormatUnknown,
		},
		{
			name: "CycloneDX attestation",
			// Base64-encoded: {"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://cyclonedx.org/bom","subject":[{"name":"test","digest":{"sha256":"abc123"}}],"predicate":{"bomFormat":"CycloneDX","specVersion":"1.4"}}
			input: `{
				"payloadType": "application/vnd.in-toto+json",
				"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL2N5Y2xvbmVkeC5vcmcvYm9tIiwic3ViamVjdCI6W3sibmFtZSI6InRlc3QiLCJkaWdlc3QiOnsic2hhMjU2IjoiYWJjMTIzIn19XSwicHJlZGljYXRlIjp7ImJvbUZvcm1hdCI6IkN5Y2xvbmVEWCIsInNwZWNWZXJzaW9uIjoiMS40In19",
				"signatures": []
			}`,
			want: sbom.FormatAttestCycloneDXJSON,
		},
		{
			name: "Regular SPDX JSON (not attestation)",
			input: `{
				"SPDXID": "SPDXRef-DOCUMENT",
				"spdxVersion": "SPDX-2.3",
				"name": "test"
			}`,
			want: sbom.FormatSPDXJSON,
		},
		{
			name: "Regular CycloneDX JSON (not attestation)",
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

func TestDecode_SPDXAttestation(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		format  sbom.Format
		wantErr bool
	}{
		{
			name: "SPDX attestation decode",
			// Base64-encoded: {"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://spdx.dev/Document","subject":[{"name":"test","digest":{"sha256":"abc123"}}],"predicate":{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3","name":"test","dataLicense":"CC0-1.0","documentNamespace":"http://trivy.dev/test","creationInfo":{"creators":["Tool: test"],"created":"2025-01-01T00:00:00Z"},"packages":[]}}
			input: `{
				"payloadType": "application/vnd.in-toto+json",
				"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3NwZHguZGV2L0RvY3VtZW50Iiwic3ViamVjdCI6W3sibmFtZSI6InRlc3QiLCJkaWdlc3QiOnsic2hhMjU2IjoiYWJjMTIzIn19XSwicHJlZGljYXRlIjp7IlNQRFhJRCI6IlNQRFhSZWYtRE9DVU1FTlQiLCJzcGR4VmVyc2lvbiI6IlNQRFgtMi4zIiwibmFtZSI6InRlc3QiLCJkYXRhTGljZW5zZSI6IkNDMC0xLjAiLCJkb2N1bWVudE5hbWVzcGFjZSI6Imh0dHA6Ly90cml2eS5kZXYvdGVzdCIsImNyZWF0aW9uSW5mbyI6eyJjcmVhdG9ycyI6WyJUb29sOiB0ZXN0Il0sImNyZWF0ZWQiOiIyMDI1LTAxLTAxVDAwOjAwOjAwWiJ9LCJwYWNrYWdlcyI6W119fQ==",
				"signatures": []
			}`,
			format:  sbom.FormatAttestSPDXJSON,
			wantErr: false,
		},
		{
			name: "Invalid SPDX attestation",
			// Base64-encoded: {"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://spdx.dev/Document","subject":[{"name":"test","digest":{"sha256":"abc123"}}],"predicate":"invalid"}
			input: `{
				"payloadType": "application/vnd.in-toto+json",
				"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3NwZHguZGV2L0RvY3VtZW50Iiwic3ViamVjdCI6W3sibmFtZSI6InRlc3QiLCJkaWdlc3QiOnsic2hhMjU2IjoiYWJjMTIzIn19XSwicHJlZGljYXRlIjoiaW52YWxpZCJ9",
				"signatures": []
			}`,
			format:  sbom.FormatAttestSPDXJSON,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.input)
			_, err := sbom.Decode(context.Background(), r, tt.format)

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
