package daemon

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"regexp"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/testdocker/engine"
)

// TestDockerImage_ContainerdImageStore covers Docker Engine 29+ with the containerd image store,
// which rejects a bare 64-hex image ID on export ("cannot specify 64-byte hexadecimal strings")
// but accepts it on inspect and history.
func TestDockerImage_ContainerdImageStore(t *testing.T) {
	const imageID = "a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72"
	imagePath := "../../test/testdata/alpine-311.tar.gz"

	te := engine.NewDockerEngine(engine.Option{
		APIVersion: opt.APIVersion,
		ImagePaths: map[string]string{
			imageID:             imagePath,
			imageID[:12]:        imagePath,
			"sha256:" + imageID: imagePath,
		},
	})
	defer te.Close()

	u, err := url.Parse(te.URL)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(u)

	bareHex := regexp.MustCompile(`^[a-f0-9]{64}$`)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if regexp.MustCompile(`/images/get$`).MatchString(r.URL.Path) {
			for _, n := range r.URL.Query()["names"] {
				if bareHex.MatchString(n) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					fmt.Fprintf(w, `{"message":"invalid repository name (%s), cannot specify 64-byte hexadecimal strings"}`, n)
					return
				}
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	defer ts.Close()

	tests := []struct {
		name      string
		imageName string
	}{
		{
			name:      "image ID without sha256 prefix",
			imageName: imageID,
		},
		{
			name:      "short image ID",
			imageName: imageID[:12],
		},
		{
			name:      "image ID with sha256 prefix",
			imageName: "sha256:" + imageID,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := name.ParseReference(tt.imageName)
			require.NoError(t, err)

			img, cleanup, err := DockerImage(t.Context(), ref, "tcp://"+ts.Listener.Addr().String())
			require.NoError(t, err)
			defer cleanup()

			got, err := img.ConfigName()
			require.NoError(t, err)
			assert.Equal(t, v1.Hash{Algorithm: "sha256", Hex: imageID}, got)

			// Reading a layer forces the image export, as the scanner does.
			conf, err := img.ConfigFile()
			require.NoError(t, err)
			require.NotEmpty(t, conf.RootFS.DiffIDs)
			_, err = img.LayerByDiffID(conf.RootFS.DiffIDs[0])
			require.NoError(t, err)
		})
	}
}
