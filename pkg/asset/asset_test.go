package asset_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	fakei "github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/asset"
)

type fakeLayer struct {
	v1.Layer
}

func (f fakeLayer) MediaType() (types.MediaType, error) {
	return "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip", nil
}

type testLocType string

var (
	testLocOCI   testLocType = "oci"
	testLocHttp  testLocType = "http"
	testLocHttps testLocType = "https"
)

type testLoc struct {
	typ   testLocType
	value string
}

type layersReturns struct {
	layers []v1.Layer
	err    error
}

func TestArtifact_Download(t *testing.T) {
	layer, err := tarball.LayerFromFile("testdata/test.tar.gz")
	require.NoError(t, err)

	txtLayer, err := tarball.LayerFromFile("testdata/test.txt")
	require.NoError(t, err)

	flayer := fakeLayer{layer}

	tests := []struct {
		name          string
		locations     []testLoc
		opts          asset.Options
		layersReturns layersReturns
		want          string
		wantErr       string
	}{
		{
			name: "happy: oci image",
			locations: []testLoc{
				{
					typ: testLocOCI,
				},
			},
			opts: asset.Options{
				MediaType: "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
			},
			layersReturns: layersReturns{
				layers: []v1.Layer{flayer},
			},
			want: "Hello, world",
		},
		{
			name: "happy: https with archive",
			locations: []testLoc{
				{
					typ:   testLocHttps,
					value: "test.tar.gz",
				},
			},
			want: "Hello, world",
		},
		{
			name: "happy: http with archive",
			locations: []testLoc{
				{
					typ:   testLocHttp,
					value: "test.tar.gz",
				},
			},
			want: "Hello, world",
		},
		{
			name: "happy: http with single file",
			locations: []testLoc{
				{
					typ:   testLocHttp,
					value: "test.txt",
				},
			},
			want: "Hello, world",
		},
		{
			name: "happy: http (unavailable) + OCI",
			locations: []testLoc{
				{
					typ:   testLocHttp,
					value: "unavailable",
				},
				{
					typ: testLocOCI,
				},
			},
			opts: asset.Options{
				MediaType: "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
			},
			layersReturns: layersReturns{
				layers: []v1.Layer{flayer},
			},
			want: "Hello, world",
		},
		{
			name: "happy: OCI (unavailable) + http",
			locations: []testLoc{
				{
					typ: testLocOCI,
				},
				{
					typ:   testLocHttp,
					value: "test.tar.gz",
				},
			},
			layersReturns: layersReturns{
				err: &transport.Error{
					StatusCode: 500,
				},
			},
			want: "Hello, world",
		},
		{
			name: "sad: http with missed file",
			locations: []testLoc{
				{
					typ:   testLocHttp,
					value: "missed",
				},
			},
			wantErr: "bad response code: 404",
		},
		{
			name: "sad: two layers",
			locations: []testLoc{
				{
					typ: testLocOCI,
				},
			},
			opts: asset.Options{
				MediaType: "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
			},
			layersReturns: layersReturns{
				layers: []v1.Layer{
					layer,
					layer,
				},
			},
			wantErr: "OCI artifact must be a single layer",
		},
		{
			name: "sad: Layers returns an error",
			locations: []testLoc{
				{
					typ: testLocOCI,
				},
			},
			opts: asset.Options{
				MediaType: "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
			},
			layersReturns: layersReturns{
				err: fmt.Errorf("error"),
			},
			wantErr: "OCI layer error",
		},
		{
			name: "invalid gzip",
			locations: []testLoc{
				{
					typ: testLocOCI,
				},
			},
			layersReturns: layersReturns{
				layers: []v1.Layer{txtLayer},
			},
			wantErr: "unexpected EOF",
		},
		{
			name: "sad: media type doesn't match",
			locations: []testLoc{
				{
					typ: testLocOCI,
				},
			},
			opts: asset.Options{
				MediaType: "unknown",
			},
			layersReturns: layersReturns{
				layers: []v1.Layer{layer},
			},
			wantErr: "unacceptable media type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			var locations []string
			img := new(fakei.FakeImage)
			for _, location := range tt.locations {
				switch location.typ {
				case testLocOCI:
					img = mockOCIImage(tt.layersReturns)
					locations = append(locations, "repo")
				case testLocHttp:
					ts := httptest.NewServer(tsHandler(location.value))
					u, err := url.JoinPath(ts.URL, location.value)
					require.NoError(t, err)
					locations = append(locations, u)
				case testLocHttps:
					ts := httptest.NewTLSServer(tsHandler(location.value))
					u, err := url.JoinPath(ts.URL, location.value)
					require.NoError(t, err)
					locations = append(locations, u)

					tt.opts.Insecure = true
				}
			}

			tt.opts.Quiet = true
			artifact := asset.NewAssets(locations, tt.opts, asset.WithImage(img))

			err = artifact.Download(context.Background(), tempDir)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			// Assert
			got, err := os.ReadFile(filepath.Join(tempDir, "test.txt"))
			require.NoError(t, err)

			assert.Equal(t, tt.want, string(got))
		})
	}
}

func mockOCIImage(lr layersReturns) *fakei.FakeImage {
	// Mock image
	img := new(fakei.FakeImage)
	img.LayersReturns(lr.layers, lr.err)
	img.ManifestReturns(&v1.Manifest{
		Layers: []v1.Descriptor{
			{
				MediaType: "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
				Size:      100,
				Digest: v1.Hash{
					Algorithm: "sha256",
					Hex:       "cba33656188782852f58993f45b68bfb8577f64cdcf02a604e3fc2afbeb5f2d8",
				},
				Annotations: map[string]string{
					"org.opencontainers.image.title": "bundle.tar.gz",
				},
			},
		},
	}, nil)

	return img
}

func tsHandler(value string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch value {
		case "unavailable":
			w.WriteHeader(http.StatusInternalServerError)
		case "missed":
			w.WriteHeader(http.StatusNotFound)
		default:
			http.ServeFile(w, r, filepath.Join("testdata", value))
			w.WriteHeader(http.StatusOK)
		}
	})
}
