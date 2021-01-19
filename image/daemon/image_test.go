package daemon

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/aquasecurity/testdocker/engine"
)

func TestMain(m *testing.M) {
	imagePaths := map[string]string{
		"index.docker.io/library/alpine:3.10": "../../test/testdata/alpine-310.tar.gz",
		"index.docker.io/library/alpine:3.11": "../../test/testdata/alpine-311.tar.gz",
		"gcr.io/distroless/base:latest":       "../../test/testdata/distroless.tar.gz",
	}

	// for Docker
	opt := engine.Option{
		APIVersion: "1.38",
		ImagePaths: imagePaths,
	}
	te := engine.NewDockerEngine(opt)
	defer te.Close()

	os.Setenv("DOCKER_HOST", fmt.Sprintf("tcp://%s", te.Listener.Addr().String()))

	os.Exit(m.Run())
}

func Test_image_ConfigName(t *testing.T) {
	tests := []struct {
		name      string
		imageName string
		want      v1.Hash
		wantErr   bool
	}{
		{
			name:      "happy path",
			imageName: "alpine:3.11",
			want: v1.Hash{
				Algorithm: "sha256",
				Hex:       "a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := name.ParseReference(tt.imageName)
			require.NoError(t, err)

			img, _, cleanup, err := DockerImage(ref)
			require.NoError(t, err)
			defer cleanup()

			conf, err := img.ConfigName()
			assert.Equal(t, tt.want, conf)
			assert.Equal(t, tt.wantErr, err != nil)
		})
	}
}

func Test_image_ConfigFile(t *testing.T) {
	tests := []struct {
		name      string
		imageName string
		want      *v1.ConfigFile
		wantErr   bool
	}{
		{
			name:      "one diff_id",
			imageName: "alpine:3.11",
			want: &v1.ConfigFile{
				RootFS: v1.RootFS{
					Type: "layers",
					DiffIDs: []v1.Hash{
						{
							Algorithm: "sha256",
							Hex:       "beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:      "multiple diff_ids",
			imageName: "gcr.io/distroless/base",
			want: &v1.ConfigFile{
				RootFS: v1.RootFS{
					Type: "layers",
					DiffIDs: []v1.Hash{
						{
							Algorithm: "sha256",
							Hex:       "42a3027eaac150d2b8f516100921f4bd83b3dbc20bfe64124f686c072b49c602",
						},
						{
							Algorithm: "sha256",
							Hex:       "f47163e8de57e3e3ccfe89d5dfbd9c252d9eca53dc7906b8db60eddcb876c592",
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := name.ParseReference(tt.imageName)
			require.NoError(t, err)

			img, _, cleanup, err := DockerImage(ref)
			require.NoError(t, err)
			defer cleanup()

			conf, err := img.ConfigFile()
			assert.Equal(t, tt.want, conf)
			assert.Equal(t, tt.wantErr, err != nil)
		})
	}
}

func Test_image_LayerByDiffID(t *testing.T) {
	type args struct {
		h v1.Hash
	}
	tests := []struct {
		name      string
		imageName string
		args      args
		wantErr   bool
	}{
		{
			name:      "happy path",
			imageName: "alpine:3.10",
			args: args{h: v1.Hash{
				Algorithm: "sha256",
				Hex:       "531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
			}},
			wantErr: false,
		},
		{
			name:      "ImageSave returns 404",
			imageName: "alpine:3.11",
			args: args{h: v1.Hash{
				Algorithm: "sha256",
				Hex:       "531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
			}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := name.ParseReference(tt.imageName)
			require.NoError(t, err)

			img, _, cleanup, err := DockerImage(ref)
			require.NoError(t, err)
			defer cleanup()

			_, err = img.LayerByDiffID(tt.args.h)
			assert.Equal(t, tt.wantErr, err != nil, err)
		})
	}
}

func Test_image_RawConfigFile(t *testing.T) {
	tests := []struct {
		name       string
		imageName  string
		goldenFile string
		wantErr    bool
	}{
		{
			name:       "happy path",
			imageName:  "alpine:3.10",
			goldenFile: "testdata/golden/config-alpine310.json",
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := name.ParseReference(tt.imageName)
			require.NoError(t, err)

			img, _, cleanup, err := DockerImage(ref)
			require.NoError(t, err)
			defer cleanup()

			got, err := img.RawConfigFile()
			assert.Equal(t, tt.wantErr, err != nil, err)

			if err != nil {
				return
			}

			want, err := ioutil.ReadFile(tt.goldenFile)
			require.NoError(t, err)

			require.JSONEq(t, string(want), string(got))
		})
	}
}
