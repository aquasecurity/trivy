package image

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/golang-jwt/jwt"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/testdocker/auth"
	"github.com/aquasecurity/testdocker/engine"
	"github.com/aquasecurity/testdocker/registry"
)

func setupEngineAndRegistry() (*httptest.Server, *httptest.Server) {
	imagePaths := map[string]string{
		"index.docker.io/library/alpine:3.10": "../test/testdata/alpine-310.tar.gz",
		"index.docker.io/library/alpine:3.11": "../test/testdata/alpine-311.tar.gz",
	}
	opt := engine.Option{
		APIVersion: "1.38",
		ImagePaths: imagePaths,
	}
	te := engine.NewDockerEngine(opt)

	imagePaths = map[string]string{
		"v2/library/alpine:3.10": "../test/testdata/alpine-310.tar.gz",
	}
	tr := registry.NewDockerRegistry(registry.Option{
		Images: imagePaths,
		Auth:   auth.Auth{},
	})

	os.Setenv("DOCKER_HOST", fmt.Sprintf("tcp://%s", te.Listener.Addr().String()))

	return te, tr
}

func TestNewDockerImage(t *testing.T) {
	te, tr := setupEngineAndRegistry()
	defer func() {
		te.Close()
		tr.Close()
	}()
	serverAddr := tr.Listener.Addr().String()

	type args struct {
		imageName string
		option    types.DockerOption
	}
	tests := []struct {
		name            string
		args            args
		wantID          string
		wantLayerIDs    []string
		wantRepoTags    []string
		wantRepoDigests []string
		wantErr         bool
	}{
		{
			name: "happy path with Docker Engine",
			args: args{
				imageName: "alpine:3.11",
			},
			wantID:       "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
			wantLayerIDs: []string{"sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203"},
			wantRepoTags: []string{"alpine:3.11"},
		},
		{
			name: "happy path with Docker Registry",
			args: args{
				imageName: fmt.Sprintf("%s/library/alpine:3.10", serverAddr),
			},
			wantID:       "sha256:af341ccd2df8b0e2d67cf8dd32e087bfda4e5756ebd1c76bbf3efa0dc246590e",
			wantLayerIDs: []string{"sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028"},
			wantRepoTags: []string{serverAddr + "/library/alpine:3.10"},
			wantRepoDigests: []string{
				serverAddr + "/library/alpine@sha256:e10ea963554297215478627d985466ada334ed15c56d3d6bb808ceab98374d91",
			},
		},
		{
			name: "happy path with insecure Docker Registry",
			args: args{
				imageName: fmt.Sprintf("%s/library/alpine:3.10", serverAddr),
				option: types.DockerOption{
					UserName:              "test",
					Password:              "test",
					NonSSL:                true,
					InsecureSkipTLSVerify: true,
				},
			},
			wantID:       "sha256:af341ccd2df8b0e2d67cf8dd32e087bfda4e5756ebd1c76bbf3efa0dc246590e",
			wantLayerIDs: []string{"sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028"},
			wantRepoTags: []string{serverAddr + "/library/alpine:3.10"},
			wantRepoDigests: []string{
				serverAddr + "/library/alpine@sha256:e10ea963554297215478627d985466ada334ed15c56d3d6bb808ceab98374d91",
			},
		},
		{
			name: "sad path with invalid tag",
			args: args{
				imageName: fmt.Sprintf("%s/library/alpine:3.11!!!", serverAddr),
			},
			wantErr: true,
		},
		{
			name: "sad path with non-exist image",
			args: args{
				imageName: fmt.Sprintf("%s/library/alpine:100", serverAddr),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img, cleanup, err := NewDockerImage(context.Background(), tt.args.imageName, tt.args.option)
			defer cleanup()

			if tt.wantErr {
				assert.NotNil(t, err)
				return
			}
			assert.NoError(t, err)

			gotID, err := img.ID()
			require.NoError(t, err)
			assert.Equal(t, tt.wantID, gotID)

			gotLayerIDs, err := img.LayerIDs()
			require.NoError(t, err)
			assert.Equal(t, tt.wantLayerIDs, gotLayerIDs)

			gotRepoTags := img.RepoTags()
			assert.Equal(t, tt.wantRepoTags, gotRepoTags)

			gotRepoDigests := img.RepoDigests()
			assert.Equal(t, tt.wantRepoDigests, gotRepoDigests)
		})
	}
}

func setupPrivateRegistry() *httptest.Server {
	imagePaths := map[string]string{
		"v2/library/alpine:3.10": "../test/testdata/alpine-310.tar.gz",
	}
	tr := registry.NewDockerRegistry(registry.Option{
		Images: imagePaths,
		Auth: auth.Auth{
			User:     "test",
			Password: "testpass",
			Secret:   "secret",
		},
	})

	return tr
}

func TestNewDockerImageWithPrivateRegistry(t *testing.T) {
	tr := setupPrivateRegistry()
	defer tr.Close()

	serverAddr := tr.Listener.Addr().String()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "testdocker",
	})

	registryToken, err := token.SignedString([]byte("secret"))
	require.NoError(t, err)

	type args struct {
		imageName string
		option    types.DockerOption
	}
	tests := []struct {
		name    string
		args    args
		want    v1.Image
		wantErr string
	}{
		{
			name: "happy path with private Docker Registry",
			args: args{
				imageName: fmt.Sprintf("%s/library/alpine:3.10", serverAddr),
				option: types.DockerOption{
					UserName:              "test",
					Password:              "testpass",
					NonSSL:                true,
					InsecureSkipTLSVerify: true,
				},
			},
		},
		{
			name: "happy path with registry token",
			args: args{
				imageName: fmt.Sprintf("%s/library/alpine:3.10", serverAddr),
				option: types.DockerOption{
					RegistryToken: registryToken,
					NonSSL:        true,
				},
			},
		},
		{
			name: "sad path without a credential",
			args: args{
				imageName: fmt.Sprintf("%s/library/alpine:3.11", serverAddr),
			},
			wantErr: "unsupported status code 401",
		},
		{
			name: "sad path with invalid registry token",
			args: args{
				imageName: fmt.Sprintf("%s/library/alpine:3.11", serverAddr),
				option: types.DockerOption{
					RegistryToken: registryToken + "invalid",
					NonSSL:        true,
				},
			},
			wantErr: "signature is invalid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, cleanup, err := NewDockerImage(context.Background(), tt.args.imageName, tt.args.option)
			defer cleanup()

			if tt.wantErr != "" {
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewArchiveImage(t *testing.T) {
	type args struct {
		fileName string
	}
	tests := []struct {
		name    string
		args    args
		want    v1.Image
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				fileName: "../test/testdata/alpine-310.tar.gz",
			},
		},
		{
			name: "happy path with OCI Image Format",
			args: args{
				fileName: "../test/testdata/test.oci",
			},
		},
		{
			name: "happy path with OCI Image and tag Format",
			args: args{
				fileName: "../test/testdata/test_image_tag.oci:0.0.1",
			},
		},
		{
			name: "happy path with OCI Image only",
			args: args{
				fileName: "../test/testdata/test_image_tag.oci",
			},
		},
		{
			name: "sad path with OCI Image and invalid tagFormat",
			args: args{
				fileName: "../test/testdata/test_image_tag.oci:0.0.0",
			},
			wantErr: "invalid OCI image tag",
		},
		{
			name: "sad path, oci image not found",
			args: args{
				fileName: "../test/testdata/invalid.tar.gz",
			},
			wantErr: "unable to open",
		},
		{
			name: "sad path with OCI Image Format index.json directory",
			args: args{
				fileName: "../test/testdata/test_index_json_dir.oci",
			},
			wantErr: "unable to retrieve index.json",
		},
		{
			name: "sad path with OCI Image Format invalid index.json",
			args: args{
				fileName: "../test/testdata/test_bad_index_json.oci",
			},
			wantErr: "invalid index.json",
		},
		{
			name: "sad path with OCI Image Format no valid manifests",
			args: args{
				fileName: "../test/testdata/test_no_valid_manifests.oci",
			},
			wantErr: "no valid manifest",
		},
		{
			name: "sad path with OCI Image Format with invalid oci image digest",
			args: args{
				fileName: "../test/testdata/test_invalid_oci_image.oci",
			},
			wantErr: "invalid OCI image",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img, err := NewArchiveImage(tt.args.fileName)
			switch {
			case tt.wantErr != "":
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			default:
				assert.NoError(t, err, tt.name)
			}

			// archive doesn't support RepoTags and RepoDigests
			assert.Empty(t, img.RepoTags())
			assert.Empty(t, img.RepoDigests())
		})
	}
}
