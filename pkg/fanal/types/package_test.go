package types_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestPackage_AddDigest(t *testing.T) {
	type added struct {
		digest digest.Digest
		source digest.Source
	}
	tests := []struct {
		name        string
		added       []added
		wantDigest  digest.Digest
		wantDigests []digest.SourcedDigest
	}{
		{
			name: "multiple algorithms",
			added: []added{
				{"md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f", digest.SourceRPMSigMD5},
				{"sha256:cf7b0f1d1a1e9b3e5b6b7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3", digest.SourceDpkgAvailable},
			},
			// The legacy field keeps the first collected value.
			wantDigest: "md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f",
			wantDigests: []digest.SourcedDigest{
				{
					Digest: "md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f",
					Source: digest.SourceRPMSigMD5,
				},
				{
					Digest: "sha256:cf7b0f1d1a1e9b3e5b6b7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3",
					Source: digest.SourceDpkgAvailable,
				},
			},
		},
		{
			name: "same algorithm from different sources",
			added: []added{
				{"sha256:cf7b0f1d1a1e9b3e5b6b7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3", digest.SourceDpkgAvailable},
				{"sha256:1e2d3c4b5a69788796a5b4c3d2e1f00918273645546372819a0b1c2d3e4f5061", digest.SourceFileContent},
			},
			wantDigest: "sha256:cf7b0f1d1a1e9b3e5b6b7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3",
			wantDigests: []digest.SourcedDigest{
				{
					Digest: "sha256:cf7b0f1d1a1e9b3e5b6b7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3",
					Source: digest.SourceDpkgAvailable,
				},
				{
					Digest: "sha256:1e2d3c4b5a69788796a5b4c3d2e1f00918273645546372819a0b1c2d3e4f5061",
					Source: digest.SourceFileContent,
				},
			},
		},
		{
			name: "same value from different sources",
			added: []added{
				{"sha1:901a7b55410321c4d35543506cff2a8613ef5aa2", digest.SourceJavaArchive},
				{"sha1:901a7b55410321c4d35543506cff2a8613ef5aa2", digest.SourceUnknown},
			},
			wantDigest: "sha1:901a7b55410321c4d35543506cff2a8613ef5aa2",
			wantDigests: []digest.SourcedDigest{
				{
					Digest: "sha1:901a7b55410321c4d35543506cff2a8613ef5aa2",
					Source: digest.SourceJavaArchive,
				},
				{
					Digest: "sha1:901a7b55410321c4d35543506cff2a8613ef5aa2",
					Source: digest.SourceUnknown,
				},
			},
		},
		{
			name: "the same digest added twice",
			added: []added{
				{"sha1:901a7b55410321c4d35543506cff2a8613ef5aa2", digest.SourceAPKInstalledDB},
				{"sha1:901a7b55410321c4d35543506cff2a8613ef5aa2", digest.SourceAPKInstalledDB},
			},
			wantDigest: "sha1:901a7b55410321c4d35543506cff2a8613ef5aa2",
			wantDigests: []digest.SourcedDigest{
				{
					Digest: "sha1:901a7b55410321c4d35543506cff2a8613ef5aa2",
					Source: digest.SourceAPKInstalledDB,
				},
			},
		},
		{
			name: "empty digest",
			added: []added{
				{"", digest.SourceRPMSigMD5},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pkg types.Package
			for _, a := range tt.added {
				pkg.AddDigest(a.digest, a.source)
			}

			assert.Equal(t, tt.wantDigest, pkg.Digest)
			assert.Equal(t, tt.wantDigests, pkg.Digests)
		})
	}
}

func TestPackage_AddDigests(t *testing.T) {
	tests := []struct {
		name        string
		pkg         types.Package
		added       []digest.SourcedDigest
		wantDigest  digest.Digest
		wantDigests []digest.SourcedDigest
	}{
		{
			name: "several digests at once",
			added: []digest.SourcedDigest{
				{
					Digest: "sha1:901a7b55410321c4d35543506cff2a8613ef5aa2",
					Source: digest.SourceUnknown,
				},
				{
					Digest: "sha256:cf7b0f1d1a1e9b3e5b6b7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3",
					Source: digest.SourceUnknown,
				},
			},
			wantDigest: "sha1:901a7b55410321c4d35543506cff2a8613ef5aa2",
			wantDigests: []digest.SourcedDigest{
				{
					Digest: "sha1:901a7b55410321c4d35543506cff2a8613ef5aa2",
					Source: digest.SourceUnknown,
				},
				{
					Digest: "sha256:cf7b0f1d1a1e9b3e5b6b7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3",
					Source: digest.SourceUnknown,
				},
			},
		},
		{
			name: "duplicates and empty values are dropped",
			added: []digest.SourcedDigest{
				{
					Digest: "sha1:901a7b55410321c4d35543506cff2a8613ef5aa2",
					Source: digest.SourceUnknown,
				},
				{
					Digest: "sha1:901a7b55410321c4d35543506cff2a8613ef5aa2",
					Source: digest.SourceUnknown,
				},
				{Source: digest.SourceUnknown},
			},
			wantDigest: "sha1:901a7b55410321c4d35543506cff2a8613ef5aa2",
			wantDigests: []digest.SourcedDigest{
				{
					Digest: "sha1:901a7b55410321c4d35543506cff2a8613ef5aa2",
					Source: digest.SourceUnknown,
				},
			},
		},
		{
			name: "values already collected are not repeated",
			pkg: types.Package{
				Digest: "md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f",
				Digests: []digest.SourcedDigest{
					{
						Digest: "md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f",
						Source: digest.SourceRPMSigMD5,
					},
				},
			},
			added: []digest.SourcedDigest{
				{
					Digest: "md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f",
					Source: digest.SourceRPMSigMD5,
				},
				{
					Digest: "md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f",
					Source: digest.SourceUnknown,
				},
			},
			wantDigest: "md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f",
			wantDigests: []digest.SourcedDigest{
				{
					Digest: "md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f",
					Source: digest.SourceRPMSigMD5,
				},
				{
					Digest: "md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f",
					Source: digest.SourceUnknown,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := tt.pkg
			pkg.AddDigests(tt.added)

			assert.Equal(t, tt.wantDigest, pkg.Digest)
			assert.Equal(t, tt.wantDigests, pkg.Digests)
		})
	}
}

// TestPackage_AddDigest_LegacyData covers data that carries the legacy digest alone, such as
// a package decoded from an SBOM. Adding another value must not leave Digest disagreeing with
// the first element of Digests.
func TestPackage_AddDigest_LegacyData(t *testing.T) {
	pkg := types.Package{Digest: "sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d"}
	pkg.AddDigest("sha256:cf7b0f1d1a1e9b3e5b6b7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3", digest.SourceFileContent)

	assert.Equal(t, digest.Digest("sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d"), pkg.Digest)
	assert.Equal(t, []digest.SourcedDigest{
		{
			Digest: "sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d",
			Source: digest.SourceUnknown,
		},
		{
			Digest: "sha256:cf7b0f1d1a1e9b3e5b6b7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3",
			Source: digest.SourceFileContent,
		},
	}, pkg.Digests)
	assert.Equal(t, pkg.Digest, pkg.Digests[0].Digest)
}

func TestPackage_HasDigest(t *testing.T) {
	var empty types.Package
	assert.False(t, empty.HasDigest())

	// Data that carries the legacy digest only still has a digest.
	legacy := types.Package{Digest: "md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f"}
	assert.True(t, legacy.HasDigest())

	var collected types.Package
	collected.AddDigest("md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f", digest.SourceRPMSigMD5)
	assert.True(t, collected.HasDigest())
}

func TestPackage_SourcedDigests(t *testing.T) {
	tests := []struct {
		name string
		pkg  types.Package
		want []digest.SourcedDigest
	}{
		{
			name: "collected digests",
			pkg: types.Package{
				Digest: "md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f",
				Digests: []digest.SourcedDigest{
					{
						Digest: "md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f",
						Source: digest.SourceRPMSigMD5,
					},
				},
			},
			want: []digest.SourcedDigest{
				{
					Digest: "md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f",
					Source: digest.SourceRPMSigMD5,
				},
			},
		},
		{
			// e.g. a report produced by a Trivy version without the sourced digests
			name: "legacy single digest",
			pkg: types.Package{
				Digest: "md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f",
			},
			want: []digest.SourcedDigest{
				{
					Digest: "md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f",
					Source: digest.SourceUnknown,
				},
			},
		},
		{
			name: "no digests",
			pkg:  types.Package{Name: "musl"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.pkg.SourcedDigests())
		})
	}
}

// TestPackage_DigestsJSON covers the serialization used by the cache and the JSON report.
func TestPackage_DigestsJSON(t *testing.T) {
	t.Run("marshal", func(t *testing.T) {
		pkg := types.Package{
			Name:    "musl",
			Version: "1.2.5-r0",
		}
		pkg.AddDigest("sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d", digest.SourceAPKInstalledDB)
		pkg.AddDigest("sha256:cf7b0f1d1a1e9b3e5b6b7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3", digest.SourceFileContent)

		b, err := json.Marshal(pkg)
		require.NoError(t, err)
		assert.JSONEq(t, `{
		  "Name": "musl",
		  "Version": "1.2.5-r0",
		  "Digest": "sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d",
		  "Digests": [
		    {
		      "Digest": "sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d",
		      "Source": "apk-installed-db"
		    },
		    {
		      "Digest": "sha256:cf7b0f1d1a1e9b3e5b6b7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3",
		      "Source": "file-content"
		    }
		  ]
		}`, string(b))
	})

	t.Run("unmarshal legacy package", func(t *testing.T) {
		var pkg types.Package
		require.NoError(t, json.Unmarshal([]byte(`{
		  "Name": "musl",
		  "Digest": "sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d"
		}`), &pkg))

		assert.Equal(t, digest.Digest("sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d"), pkg.Digest)
		assert.Empty(t, pkg.Digests)
		// The acquisition method of a legacy value is not recorded anywhere.
		assert.Equal(t, []digest.SourcedDigest{
			{
				Digest: "sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d",
				Source: digest.SourceUnknown,
			},
		}, pkg.SourcedDigests())
	})
}
