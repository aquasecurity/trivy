package dependency_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestID(t *testing.T) {
	type args struct {
		ltype   types.LangType
		name    string
		version string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "conan",
			args: args{
				ltype:   types.Conan,
				name:    "test",
				version: "1.0.0",
			},
			want: "test/1.0.0",
		},
		{
			name: "go module",
			args: args{
				ltype:   types.GoModule,
				name:    "test",
				version: "v1.0.0",
			},
			want: "test@v1.0.0",
		},
		{
			name: "gradle",
			args: args{
				ltype:   types.Gradle,
				name:    "test",
				version: "1.0.0",
			},
			want: "test:1.0.0",
		},
		{
			name: "sbt",
			args: args{
				ltype:   types.Sbt,
				name:    "test",
				version: "1.0.0",
			},
			want: "test:1.0.0",
		},
		{
			name: "pip",
			args: args{
				ltype:   types.Pip,
				name:    "test",
				version: "1.0.0",
			},
			want: "test@1.0.0",
		},
		{
			name: "no version",
			args: args{
				ltype:   types.Pom,
				name:    "test",
				version: "",
			},
			want: "test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dependency.ID(tt.args.ltype, tt.args.name, tt.args.version)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestUID_Digests pins that the collected digests take part in the package hash, values and
// sources alike: an image can carry the same package twice, once found by its own analyzer and
// once read from an SBOM shipped inside it, and those two must not collapse into one identity.
func TestUID_Digests(t *testing.T) {
	base := types.Package{
		Name:    "musl",
		Version: "1.2.5-r0",
		Digest:  "sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d",
		Digests: []digest.SourcedDigest{
			{
				Digest: "sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d",
				Source: digest.SourceAPKInstalledDB,
			},
		},
	}

	// The packages below differ from base in the collected digests alone.
	fromSBOM := base
	fromSBOM.Digests = []digest.SourcedDigest{
		{
			Digest: "sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d",
			Source: digest.SourceSBOM,
		},
	}

	withSecond := base
	withSecond.Digests = append(slices.Clone(base.Digests), digest.SourcedDigest{
		Digest: "sha256:cf7b0f1d1a1e9b3e5b6b7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3",
		Source: digest.SourceFileContent,
	})

	otherValue := base
	otherValue.Digests = []digest.SourcedDigest{
		{
			Digest: "sha1:0000000000000000000000000000000000000000",
			Source: digest.SourceAPKInstalledDB,
		},
	}

	uid := dependency.UID("", base)
	assert.NotEqual(t, uid, dependency.UID("", fromSBOM))
	assert.NotEqual(t, uid, dependency.UID("", withSecond))
	assert.NotEqual(t, uid, dependency.UID("", otherValue))
}
