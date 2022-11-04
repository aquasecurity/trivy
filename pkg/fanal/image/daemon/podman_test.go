package daemon

import (
	"io/ioutil"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/aquasecurity/testdocker/engine"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/docker/api/types"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func setupPodmanSock(t *testing.T) *httptest.Server {
	t.Helper()

	runtimeDir, err := ioutil.TempDir("", "daemon")
	require.NoError(t, err)

	os.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	dir := filepath.Join(runtimeDir, "podman")
	err = os.MkdirAll(dir, os.ModePerm)
	require.NoError(t, err)

	sockPath := filepath.Join(dir, "podman.sock")

	opt := engine.Option{
		APIVersion: "1.40",
		ImagePaths: map[string]string{
			"index.docker.io/library/alpine:3.11": "../../test/testdata/alpine-311.tar.gz",
		},
		UnixDomainSocket: sockPath,
	}
	te := engine.NewDockerEngine(opt)
	return te
}

func TestPodmanImage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("podman.sock is not available for Windows CI")
	}

	type fields struct {
		Image   v1.Image
		opener  opener
		inspect types.ImageInspect
	}
	tests := []struct {
		name           string
		imageName      string
		fields         fields
		wantConfigName string
		wantCreateBy   []string
		wantErr        bool
	}{
		{
			name:           "happy path",
			imageName:      "alpine:3.11",
			wantConfigName: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
			wantCreateBy: []string{
				"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
				"/bin/sh -c #(nop) ADD file:0c4555f363c2672e350001f1293e689875a3760afe7b3f9146886afe67121cba in / ",
			},
			wantErr: false,
		},
		{
			name:      "unknown image",
			imageName: "alpine:unknown",
			wantErr:   true,
		},
	}

	te := setupPodmanSock(t)
	defer te.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := name.ParseReference(tt.imageName)
			require.NoError(t, err)

			img, cleanup, err := PodmanImage(ref.Name())
			defer cleanup()

			if tt.wantErr {
				assert.NotNil(t, err)
				return
			}
			assert.NoError(t, err)

			confName, err := img.ConfigName()
			require.NoError(t, err)
			assert.Equal(t, tt.wantConfigName, confName.String())

			confFile, err := img.ConfigFile()
			require.NoError(t, err)

			assert.Equal(t, len(confFile.History), len(tt.wantCreateBy))
			for _, h := range confFile.History {
				assert.Contains(t, tt.wantCreateBy, h.CreatedBy)
			}
		})
	}
}
