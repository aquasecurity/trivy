package sbom_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/attestation/sbom"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/rekortest"
)

func TestRekor_RetrieveSBOM(t *testing.T) {
	tests := []struct {
		name    string
		digest  string
		want    string
		wantErr string
	}{
		{
			name:   "happy path",
			digest: "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
			want:   `{"bomFormat":"CycloneDX","specVersion":"1.4","version":2}`,
		},
		{
			name:    "404",
			digest:  "sha256:unknown",
			wantErr: "failed to search",
		},
	}

	require.NoError(t, log.InitLogger(false, true))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := rekortest.NewServer(t)
			defer ts.Close()

			// Set the testing URL
			rc, err := sbom.NewRekor(ts.URL())
			require.NoError(t, err)

			got, err := rc.RetrieveSBOM(context.Background(), tt.digest)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err, tt.name)
			assert.Equal(t, tt.want, string(got))
		})
	}
}
