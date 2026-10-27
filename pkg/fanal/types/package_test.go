package types_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestPackage_AddDigests(t *testing.T) {
	tests := []struct {
		name        string
		pkg         types.Package
		digests     []digest.SourcedDigest
		wantDigest  digest.Digest
		wantDigests []digest.SourcedDigest
	}{
		{
			name: "same value from different sources",
			digests: []digest.SourcedDigest{
				digest.NewSourcedDigest("sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d", digest.SourceJavaArchive),
				digest.NewSourcedDigest("sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d", digest.SourceSBOM),
			},
			wantDigests: []digest.SourcedDigest{
				{
					Digest: "sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d",
					Source: digest.SourceJavaArchive,
				},
				{
					Digest: "sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d",
					Source: digest.SourceSBOM,
				},
			},
		},
		{
			name: "duplicates and empty values",
			digests: []digest.SourcedDigest{
				digest.NewSourcedDigest("sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d", digest.SourceAPKInstalledDB),
				digest.NewSourcedDigest("sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d", digest.SourceAPKInstalledDB),
				digest.NewSourcedDigest("", digest.SourceAPKInstalledDB),
			},
			wantDigests: []digest.SourcedDigest{
				{
					Digest: "sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d",
					Source: digest.SourceAPKInstalledDB,
				},
			},
		},
		{
			name: "same algorithm and source",
			digests: []digest.SourcedDigest{
				digest.NewSourcedDigest("sha256:cf7b0f1d1a1e9b3e5b6b7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3", digest.SourceSBOM),
				digest.NewSourcedDigest("sha256:1e2d3c4b5a69788796a5b4c3d2e1f00918273645546372819a0b1c2d3e4f5061", digest.SourceSBOM),
				digest.NewSourcedDigest("sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d", digest.SourceSBOM),
			},
			wantDigests: []digest.SourcedDigest{
				{
					Digest: "sha256:cf7b0f1d1a1e9b3e5b6b7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3",
					Source: digest.SourceSBOM,
				},
				{
					Digest: "sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d",
					Source: digest.SourceSBOM,
				},
			},
		},
		{
			name: "empty digest",
			digests: []digest.SourcedDigest{
				digest.NewSourcedDigest("", digest.SourceRPMSigMD5),
			},
		},
		{
			name: "on top of what is already collected",
			pkg: types.Package{
				Digests: []digest.SourcedDigest{
					{
						Digest: "md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f",
						Source: digest.SourceRPMSigMD5,
					},
				},
			},
			digests: []digest.SourcedDigest{
				digest.NewSourcedDigest("md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f", digest.SourceRPMSigMD5),
				digest.NewSourcedDigest("md5:0c4b9d8e7f6a5b4c3d2e1f0a9b8c7d6e", digest.SourceRPMSigMD5),
				digest.NewSourcedDigest("md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f", digest.SourceSBOM),
			},
			wantDigests: []digest.SourcedDigest{
				{
					Digest: "md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f",
					Source: digest.SourceRPMSigMD5,
				},
				{
					Digest: "md5:e35b7bd7c7a54c73d4b7f7e18f4a1e4f",
					Source: digest.SourceSBOM,
				},
			},
		},
		{
			// The legacy field is neither read nor written.
			name: "on top of legacy data",
			pkg:  types.Package{Digest: "sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d"},
			digests: []digest.SourcedDigest{
				digest.NewSourcedDigest("sha256:cf7b0f1d1a1e9b3e5b6b7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3", digest.SourceFileContent),
			},
			wantDigest: "sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d",
			wantDigests: []digest.SourcedDigest{
				{
					Digest: "sha256:cf7b0f1d1a1e9b3e5b6b7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3",
					Source: digest.SourceFileContent,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := tt.pkg
			pkg.AddDigests(tt.digests...)

			assert.Equal(t, tt.wantDigest, pkg.Digest)
			assert.Equal(t, tt.wantDigests, pkg.Digests)
		})
	}
}

func TestPackage_HasDigestFrom(t *testing.T) {
	tests := []struct {
		name string
		pkg  types.Package
		src  digest.Source
		want bool
	}{
		{
			name: "digest from the source",
			pkg: types.Package{
				Digests: []digest.SourcedDigest{
					digest.NewSourcedDigest("sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d", digest.SourceSBOM),
					digest.NewSourcedDigest("sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d", digest.SourceJavaArchive),
				},
			},
			src:  digest.SourceJavaArchive,
			want: true,
		},
		{
			name: "digest from another source",
			pkg: types.Package{
				Digests: []digest.SourcedDigest{
					digest.NewSourcedDigest("sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d", digest.SourceSBOM),
				},
			},
			src: digest.SourceJavaArchive,
		},
		{
			// The legacy field records no source.
			name: "legacy digest only",
			pkg:  types.Package{Digest: "sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d"},
			src:  digest.SourceUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.pkg.HasDigestFrom(tt.src))
		})
	}
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
