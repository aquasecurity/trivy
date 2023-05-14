package attestation_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/attestation"
)

func TestStatement_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      attestation.Statement
	}{
		{
			name:      "happy path",
			inputFile: "testdata/attestation.json",
			want: attestation.Statement{
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			got := attestation.Statement{Predicate: &attestation.CosignPredicate{}}
			err = json.NewDecoder(f).Decode(&got)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
