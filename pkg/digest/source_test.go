package digest_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/digest"
)

func TestSourcedDigest_Accessors(t *testing.T) {
	tests := []struct {
		name          string
		sourcedDigest digest.SourcedDigest
		wantAlgorithm digest.Algorithm
		wantValue     string
	}{
		{
			name: "digest from package metadata",
			sourcedDigest: digest.SourcedDigest{
				Digest: digest.NewDigestFromString(digest.MD5, "e35b7bd7c7a54c73d4b7f7e18f4a1e4f"),
				Source: digest.SourceRPMSigMD5,
			},
			wantAlgorithm: digest.MD5,
			wantValue:     "e35b7bd7c7a54c73d4b7f7e18f4a1e4f",
		},
		{
			name: "digest with an unknown source",
			sourcedDigest: digest.SourcedDigest{
				Digest: digest.NewDigestFromString(digest.SHA256, "cf7b0f1d1a1e9b3e5b6b7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3"),
				Source: digest.SourceUnknown,
			},
			wantAlgorithm: digest.SHA256,
			wantValue:     "cf7b0f1d1a1e9b3e5b6b7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantAlgorithm, tt.sourcedDigest.Algorithm())
			assert.Equal(t, tt.wantValue, tt.sourcedDigest.Value())
		})
	}
}

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
		{
			name: "unknown source",
			sourcedDigest: digest.SourcedDigest{
				Digest: "sha1:901a7b55410321c4d35543506cff2a8613ef5aa2",
				Source: digest.SourceUnknown,
			},
			want: `{"Digest":"sha1:901a7b55410321c4d35543506cff2a8613ef5aa2","Source":"unknown"}`,
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
