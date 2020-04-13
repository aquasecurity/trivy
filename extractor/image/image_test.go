package image

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/testdocker/engine"
	"github.com/aquasecurity/testdocker/registry"

	"github.com/aquasecurity/fanal/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

var serverAddr string

func TestMain(m *testing.M) {
	imagePaths := map[string]string{
		"index.docker.io/library/alpine:3.10": "../testdata/alpine-310.tar.gz",
		"index.docker.io/library/alpine:3.11": "../testdata/alpine-311.tar.gz",
	}
	opt := engine.Option{
		APIVersion: "1.38",
		ImagePaths: imagePaths,
	}
	te := engine.NewDockerEngine(opt)
	defer te.Close()

	imagePaths = map[string]string{
		"v2/library/alpine:3.10": "../testdata/alpine-310.tar.gz",
	}
	tr := registry.NewDockerRegistry(imagePaths)
	defer tr.Close()

	serverAddr = tr.Listener.Addr().String()

	os.Setenv("DOCKER_HOST", fmt.Sprintf("tcp://%s", te.Listener.Addr().String()))

	os.Exit(m.Run())
}

func TestNewDockerImage(t *testing.T) {
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

func TestNewDockerArchiveImage(t *testing.T) {
	type args struct {
		fileName string
	}
	tests := []struct {
		name    string
		args    args
		want    v1.Image
		wantErr bool
	}{
		{
			name: "happy path",
			args: args{
				fileName: "../testdata/alpine-310.tar.gz",
			},
		},
		{
			name: "sad path",
			args: args{
				fileName: "../testdata/invalid.tar.gz",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewDockerArchiveImage(tt.args.fileName)
			assert.Equal(t, tt.wantErr, err != nil, err)
		})
	}
}
