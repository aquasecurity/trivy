package attestation_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/attestation"
)

func TestDecode(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      attestation.Statement
	}{
		{
			name:      "happy path",
			inputFile: "testdata/attestation.json",
			want: attestation.Statement{
				PredicateType: "cosign.sigstore.dev/attestation/v1",
				Predicate: attestation.CosignPredicate{
					Data: []byte(`"foo\n"`),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			got, err := attestation.Decode(f)
			require.NoError(t, err)

			require.Equal(t, tt.want, got)
		})
	}
}
