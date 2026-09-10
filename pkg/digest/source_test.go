package digest_test

import (
	"encoding/json"
	"testing"

	"github.com/mitchellh/hashstructure/v2"
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

// TestSourcedDigest_Hash pins the contract that hashstructure identifies a sourced
// digest by its value alone. SBOM element IDs are hashes of whole components, so a
// digest whose source is unknown must not produce a different ID than the same value
// with a known source.
func TestSourcedDigest_Hash(t *testing.T) {
	const value = "sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d"

	opts := &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	}
	hash := func(v any) uint64 {
		got, err := hashstructure.Hash(v, hashstructure.FormatV2, opts)
		require.NoError(t, err)
		return got
	}

	// A sourced digest has to hash exactly like the bare value it wraps.
	want := hash(digest.Digest(value))

	for _, src := range []digest.Source{
		digest.SourceUnknown,
		digest.SourceAPKInstalledDB,
		digest.SourceFileContent,
	} {
		t.Run("source "+string(src), func(t *testing.T) {
			assert.Equal(t, want, hash(digest.SourcedDigest{
				Digest: value,
				Source: src,
			}))
		})
	}

	// Different values must still hash differently.
	assert.NotEqual(t, want, hash(digest.SourcedDigest{
		Digest: "sha1:0000000000000000000000000000000000000000",
		Source: digest.SourceAPKInstalledDB,
	}))
}
