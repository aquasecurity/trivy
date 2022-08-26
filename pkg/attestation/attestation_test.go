package attestation_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/attestation"
)

func TestStatement_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      attestation.Envelope
	}{
		{
			name:      "happy path",
			inputFile: "testdata/attestation.json",
			want: attestation.Envelope{
				Envelope: dsse.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJjb3NpZ24uc2lnc3RvcmUuZGV2L2F0dGVzdGF0aW9uL3YxIiwic3ViamVjdCI6W3sibmFtZSI6ImdoY3IuaW8vYXF1YXNlY3VyaXR5L3RyaXZ5LXRlc3QtaW1hZ2VzIiwiZGlnZXN0Ijp7InNoYTI1NiI6IjcyYzQyZWQ0OGMzYTJkYjMxYjdkYWZlMTdkMjc1YjYzNDY2NGE3MDhkOTAxZWM5ZmQ1N2IxNTI5MjgwZjAxZmIifX1dLCJwcmVkaWNhdGUiOnsiRGF0YSI6ImZvb1xuIiwiVGltZXN0YW1wIjoiMjAyMi0wOC0wM1QxMzowODoyN1oifX0=",
					Signatures: []dsse.Signature{
						{
							KeyID: "",
							Sig:   "MEUCIQClJhJ2mS78MWy4L32wxd+8gPXYwpvyn0nmuY9r5t8iiAIgHKKoIJbKAKQ8i/bgN76ocuGhwUMdbgqpgKF0yFfPfGI=",
						},
					},
				},
				Payload: &in_toto.Statement{
					StatementHeader: in_toto.StatementHeader{
						Type:          "https://in-toto.io/Statement/v0.1",
						PredicateType: "cosign.sigstore.dev/attestation/v1",
						Subject: []in_toto.Subject{
							{
								Name: "ghcr.io/aquasecurity/trivy-test-images",
								Digest: slsa.DigestSet{
									"sha256": "72c42ed48c3a2db31b7dafe17d275b634664a708d901ec9fd57b1529280f01fb",
								},
							},
						},
					},
					Predicate: &attestation.CosignPredicate{
						Data: "foo\n",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			got := attestation.Envelope{
				Payload: &in_toto.Statement{
					Predicate: &attestation.CosignPredicate{},
				},
			}

			err = json.NewDecoder(f).Decode(&got)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
