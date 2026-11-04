package digest_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/digest"
)

func TestSourcedDigest_JSON(t *testing.T) {
	tests := []struct {
		name          string
		sourcedDigest digest.SourcedDigest
		want          string
	}{
		{
			name: "known source",
			sourcedDigest: digest.SourcedDigest{
				Digest: "sha256:cf7b0f1d1a1e9b3e5b6b7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3",
				Source: digest.SourceDpkgAvailable,
			},
			want: `{"Digest":"sha256:cf7b0f1d1a1e9b3e5b6b7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3","Source":"dpkg-available-sha256"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.sourcedDigest)
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(b))

			var got digest.SourcedDigest
			require.NoError(t, json.Unmarshal(b, &got))
			assert.Equal(t, tt.sourcedDigest, got)
		})
	}
}
