package dependency_test

import (
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

// TestUID_Digests pins how the collected digests take part in the package hash: their
// values do, but the source they were acquired from does not. The source is unknown for
// data that came from an SBOM or an older cache blob, so a UID that depended on it would
// differ between scans of the very same package.
func TestUID_Digests(t *testing.T) {
	pkg := types.Package{
		Name:    "musl",
		Version: "1.2.5-r0",
	}

	withDigest := pkg
	withDigest.AddDigest("sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d", digest.SourceAPKInstalledDB)
	assert.NotEqual(t, dependency.UID("", pkg), dependency.UID("", withDigest))

	sameValueOtherSource := pkg
	sameValueOtherSource.AddDigest("sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d", digest.SourceUnknown)
	assert.Equal(t, dependency.UID("", withDigest), dependency.UID("", sameValueOtherSource))

	otherValue := pkg
	otherValue.AddDigest("sha1:0000000000000000000000000000000000000000", digest.SourceAPKInstalledDB)
	assert.NotEqual(t, dependency.UID("", withDigest), dependency.UID("", otherValue))
}
