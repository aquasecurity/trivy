package image

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
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
		name    string
		args    args
		want    v1.Image
		wantErr bool
	}{
		{
			name: "happy path with Docker Engine",
			args: args{
				imageName: "alpine:3.11",
			},
		},
		{
			name: "happy path with Docker Registry",
			args: args{
				imageName: fmt.Sprintf("%s/library/alpine:3.10", serverAddr),
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
			_, cleanup, err := NewDockerImage(context.Background(), tt.args.imageName, tt.args.option)
			defer cleanup()

			assert.Equal(t, tt.wantErr, err != nil, err)
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
			_, err := NewArchiveImage(tt.args.fileName)
			switch {
			case tt.wantErr != "":
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			default:
				assert.NoError(t, err, tt.name)
			}
		})
	}
}
