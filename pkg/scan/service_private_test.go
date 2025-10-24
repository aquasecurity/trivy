package scan

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestService_generateArtifactID(t *testing.T) {

	tests := []struct {
		name         string
		artifactInfo artifact.Reference
		want         string
	}{
		{
			name: "container image with valid reference",
			artifactInfo: artifact.Reference{
				Name: "ghcr.io/aquasecurity/trivy:latest",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID:        "sha256:abc123",
					Reference: testutil.MustParseReference(t, "ghcr.io/aquasecurity/trivy:latest"),
				},
			},
			want: "sha256:58a3381def2cec86309c94be4fbeaca4b6c0231743ed1df9b0bea883a33cdebb",
		},
		{
			name: "same image with different tag should have same artifact ID",
			artifactInfo: artifact.Reference{
				Name: "ghcr.io/aquasecurity/trivy:v0.65.0",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID:        "sha256:abc123",
					Reference: testutil.MustParseReference(t, "ghcr.io/aquasecurity/trivy:v0.65.0"),
				},
			},
			want: "sha256:58a3381def2cec86309c94be4fbeaca4b6c0231743ed1df9b0bea883a33cdebb",
		},
		{
			name: "different repository should have different artifact ID",
			artifactInfo: artifact.Reference{
				Name: "ghcr.io/aqua-sec/trivy:v0.65.0",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID:        "sha256:abc123",
					Reference: testutil.MustParseReference(t, "ghcr.io/aqua-sec/trivy:v0.65.0"),
				},
			},
			want: "sha256:bf73a838ae6a9d9c3018fbc7b628741f3be920b75c011a49c0b192736eb789b1",
		},
		{
			name: "different registry should have different artifact ID",
			artifactInfo: artifact.Reference{
				Name: "docker.io/aquasecurity/trivy:v0.65.0",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID:        "sha256:abc123",
					Reference: testutil.MustParseReference(t, "docker.io/aquasecurity/trivy:v0.65.0"),
				},
			},
			want: "sha256:dcba426e1fbd6e7fda125be3b9a2507ce3da2c7954c2edbf0e06e34d7f0ca22f",
		},
		{
			name: "docker.io implicit (no registry)",
			artifactInfo: artifact.Reference{
				Name: "aquasecurity/trivy:latest",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID:        "sha256:abc123",
					Reference: testutil.MustParseReference(t, "aquasecurity/trivy:latest"),
				},
			},
			want: "sha256:dcba426e1fbd6e7fda125be3b9a2507ce3da2c7954c2edbf0e06e34d7f0ca22f",
		},
		{
			name: "docker.io official image",
			artifactInfo: artifact.Reference{
				Name: "alpine:3.10",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID:        "sha256:alpine123",
					Reference: testutil.MustParseReference(t, "alpine:3.10"),
				},
			},
			want: "sha256:56de33d7ec6a1f832c9a7b2a26b1870efe79198e1c13ac645d43798c90954bb5",
		},
		{
			name: "localhost with port",
			artifactInfo: artifact.Reference{
				Name: "localhost:5000/myapp:latest",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID:        "sha256:local123",
					Reference: testutil.MustParseReference(t, "localhost:5000/myapp:latest"),
				},
			},
			want: "sha256:7cbf1bbde2285bac7c810fb76da5b0476d284f320f50b913987d6fc9226dc3e3",
		},
		{
			name: "multi-level repository",
			artifactInfo: artifact.Reference{
				Name: "gcr.io/my-org/my-team/my-app:v1.0.0",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID:        "sha256:gcr123",
					Reference: testutil.MustParseReference(t, "gcr.io/my-org/my-team/my-app:v1.0.0"),
				},
			},
			want: "sha256:edb01f579a800df17687439f1115bf4ced7bb977aa6afd468675ec56145a530c",
		},
		{
			name: "same image with different digest should have same artifact ID",
			artifactInfo: artifact.Reference{
				Name: "ghcr.io/aquasecurity/trivy@sha256:0000000000000000000000000000000000000000000000000000000000000000",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID:        "sha256:abc123",
					Reference: testutil.MustParseReference(t, "ghcr.io/aquasecurity/trivy@sha256:0000000000000000000000000000000000000000000000000000000000000000"),
				},
			},
			want: "sha256:58a3381def2cec86309c94be4fbeaca4b6c0231743ed1df9b0bea883a33cdebb",
		},
		{
			name: "image with digest (no reference)",
			artifactInfo: artifact.Reference{
				Name: "ghcr.io/aquasecurity/trivy@sha256:abc123",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID: "sha256:abc123",
					// No reference for digest case (empty)
				},
			},
			want: "sha256:abc123",
		},
		{
			name: "container image with no image ID",
			artifactInfo: artifact.Reference{
				Name: "ghcr.io/aquasecurity/trivy:latest",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID: "",
					// No reference
				},
			},
			want: "",
		},
		{
			name: "container image with tar archive (uses RepoTag)",
			artifactInfo: artifact.Reference{
				Name: "../fanal/test/testdata/alpine-311.tar.gz",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID:        "sha256:fallback123",
					Reference: testutil.MustParseReference(t, "alpine:3.11"),
				},
			},
			want: "sha256:a840c3e6bbadd213fee8cf6e4c32082f06541b8792a929fd373a57e5af0e8fa5",
		},
		{
			name: "repository with URL and commit",
			artifactInfo: artifact.Reference{
				Name: "myrepo",
				Type: ftypes.TypeRepository,
				RepoMetadata: artifact.RepoMetadata{
					RepoURL: "https://github.com/aquasecurity/trivy",
					Commit:  "abc123def456",
				},
			},
			want: "sha256:e23a8c4bae6c00f26ebf52d59e70ddfbbf5b2916d089239c3224f7f06371af98",
		},
		{
			name: "repository with only commit",
			artifactInfo: artifact.Reference{
				Name: "/path/to/local/repo",
				Type: ftypes.TypeRepository,
				RepoMetadata: artifact.RepoMetadata{
					Commit: "abc123def456",
				},
			},
			want: "sha256:9183de2823d60a525ed7aeabdb2cda775cba82dd5da0e94bb2fbba779ad399a7",
		},
		{
			name: "repository without commit",
			artifactInfo: artifact.Reference{
				Name: "myrepo",
				Type: ftypes.TypeRepository,
				RepoMetadata: artifact.RepoMetadata{
					RepoURL: "https://github.com/aquasecurity/trivy",
				},
			},
			want: "",
		},
		{
			name: "filesystem scan",
			artifactInfo: artifact.Reference{
				Name: "/some/path",
				Type: ftypes.TypeFilesystem,
			},
			want: "",
		},
		{
			name: "unknown type",
			artifactInfo: artifact.Reference{
				Name: "something",
				Type: "unknown",
			},
			want: "",
		},
	}

	s := Service{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.generateArtifactID(tt.artifactInfo)
			assert.Equal(t, tt.want, got)
		})
	}
}
