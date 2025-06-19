package image

import (
	"context"
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_implicitReference_TagName(t *testing.T) {
	tests := []struct {
		name  string
		image string
		want  string
	}{
		{
			name:  "explicit tag",
			image: "aquasec/trivy:0.15.0",
			want:  "0.15.0",
		},
		{
			name:  "implicit tag",
			image: "aquasec/trivy",
			want:  "latest",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := name.ParseReference(tt.image)
			require.NoError(t, err)

			ref := implicitReference{ref: r}

			got := ref.TagName()
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_implicitReference_RepositoryName(t *testing.T) {
	tests := []struct {
		name  string
		image string
		want  string
	}{
		{
			name:  "explicit default registry",
			image: "index.docker.io/aquasec/trivy:0.15.0",
			want:  "aquasec/trivy",
		},
		{
			name:  "explicit default namespace",
			image: "library/alpine:3.12",
			want:  "alpine",
		},
		{
			name:  "implicit registry",
			image: "aquasec/trivy:latest",
			want:  "aquasec/trivy",
		},
		{
			name:  "implicit namespace",
			image: "alpine:latest",
			want:  "alpine",
		},
		{
			name:  "non-default registry",
			image: "gcr.io/library/alpine:3.12",
			want:  "gcr.io/library/alpine",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := name.ParseReference(tt.image)
			require.NoError(t, err)

			ref := implicitReference{ref: r}

			got := ref.RepositoryName()
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_tryRemote(t *testing.T) {
	// Create a test image
	img, err := random.Image(1024, 5)
	require.NoError(t, err)

	// Get the image digest for test expectations
	digest, err := img.Digest()
	require.NoError(t, err)

	// Set up registry server with null logger to suppress log output
	nullLogger := log.New(io.Discard, "", 0)
	s := httptest.NewServer(registry.New(registry.Logger(nullLogger)))
	t.Cleanup(s.Close)

	u, err := url.Parse(s.URL)
	require.NoError(t, err)

	tests := []struct {
		name       string
		imageName  string
		setupImage func(t *testing.T, ref name.Reference)
		wantName   string
		wantErr    string
	}{
		{
			name:      "successful image retrieval",
			imageName: "test/alpine:3.10",
			setupImage: func(t *testing.T, ref name.Reference) {
				err := remote.Write(ref, img)
				require.NoError(t, err)
			},
			wantName: "/test/alpine:3.10",
		},
		{
			name:      "helm chart config media type",
			imageName: "test/helm:chart",
			setupImage: func(t *testing.T, ref name.Reference) {
				configFile, err := img.ConfigFile()
				require.NoError(t, err)

				// Create a new config with helm chart media type
				imageToWrite, err := mutate.Config(img, configFile.Config)
				require.NoError(t, err)

				imageToWrite = mutate.ConfigMediaType(imageToWrite, "application/vnd.cncf.helm.chart")

				err = remote.Write(ref, imageToWrite)
				require.NoError(t, err)
			},
			wantErr: "unsupported artifact type",
		},
		{
			name:       "image not found",
			imageName:  "test/notfound:latest",
			wantErr:    "NAME_UNKNOWN",
			setupImage: func(t *testing.T, ref name.Reference) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the image name with the test server address
			fullImageName := u.Host + "/" + tt.imageName
			ref, err := name.ParseReference(fullImageName)
			require.NoError(t, err)

			// Set up the image in registry if needed
			tt.setupImage(t, ref)

			ctx := context.Background()
			got, cleanup, err := tryRemote(ctx, fullImageName, ref, types.ImageOptions{
				RegistryOptions: types.RegistryOptions{
					Insecure: true,
				},
			})
			t.Cleanup(cleanup)

			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, got)
			assert.Contains(t, got.Name(), tt.wantName)

			// Verify RepoTags and RepoDigests contain expected values
			repoTags := got.RepoTags()
			repoDigests := got.RepoDigests()
			assert.Len(t, repoTags, 1)
			assert.Contains(t, repoTags[0], tt.imageName)
			assert.Len(t, repoDigests, 1)
			assert.Contains(t, repoDigests[0], digest.String())
		})
	}
}