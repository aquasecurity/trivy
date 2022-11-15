package oci_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	fakei "github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/oci"
	"github.com/aquasecurity/trivy/pkg/utils"
)

type fakeLayer struct {
	v1.Layer
}

func (f fakeLayer) MediaType() (types.MediaType, error) {
	return "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip", nil
}

func TestNewArtifact(t *testing.T) {
	layer, err := tarball.LayerFromFile("testdata/test.tar.gz")
	require.NoError(t, err)

	flayer := fakeLayer{layer}

	type layersReturns struct {
		layers []v1.Layer
		err    error
	}
	tests := []struct {
		name          string
		mediaType     string
		layersReturns layersReturns
		wantErr       string
	}{
		{
			name:      "happy path",
			mediaType: "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
			layersReturns: layersReturns{
				layers: []v1.Layer{flayer},
			},
		},
		{
			name:      "sad: two layers",
			mediaType: "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
			layersReturns: layersReturns{
				layers: []v1.Layer{layer, layer},
			},
			wantErr: "OCI artifact must be a single layer",
		},
		{
			name:      "sad: Layers returns an error",
			mediaType: "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
			layersReturns: layersReturns{
				err: fmt.Errorf("error"),
			},
			wantErr: "OCI layer error",
		},
		{
			name:      "sad: media type doesn't match",
			mediaType: "unknown",
			layersReturns: layersReturns{
				layers: []v1.Layer{layer},
			},
			wantErr: "unacceptable media type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			utils.SetCacheDir(tempDir)

			// Mock image
			img := new(fakei.FakeImage)
			img.LayersReturns(tt.layersReturns.layers, tt.layersReturns.err)
			img.ManifestReturns(&v1.Manifest{
				Layers: []v1.Descriptor{
					{
						MediaType: "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
						Size:      100,
						Digest: v1.Hash{
							Algorithm: "sha256",
							Hex:       "cba33656188782852f58993f45b68bfb8577f64cdcf02a604e3fc2afbeb5f2d8"},
						Annotations: map[string]string{
							"org.opencontainers.image.title": "bundle.tar.gz",
						},
					},
				},
			}, nil)

			_, err = oci.NewArtifact("repo", tt.mediaType, true, false, oci.WithImage(img))
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestArtifact_Download(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr string
	}{
		{
			name:  "happy path",
			input: "testdata/test.tar.gz",
			want:  "Hello, world",
		},
		{
			name:    "invalid gzip",
			input:   "testdata/test.txt",
			wantErr: "unexpected EOF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			utils.SetCacheDir(tempDir)

			// Mock layer
			layer, err := tarball.LayerFromFile(tt.input)
			require.NoError(t, err)
			flayer := fakeLayer{layer}

			// Mock image
			img := new(fakei.FakeImage)
			img.LayersReturns([]v1.Layer{flayer}, nil)
			img.ManifestReturns(&v1.Manifest{
				Layers: []v1.Descriptor{
					{
						MediaType: "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
						Size:      100,
						Digest: v1.Hash{
							Algorithm: "sha256",
							Hex:       "cba33656188782852f58993f45b68bfb8577f64cdcf02a604e3fc2afbeb5f2d8"},
						Annotations: map[string]string{
							"org.opencontainers.image.title": "bundle.tar.gz",
						},
					},
				},
			}, nil)

			mediaType := "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip"
			artifact, err := oci.NewArtifact("repo", mediaType, true, false, oci.WithImage(img))
			require.NoError(t, err)

			err = artifact.Download(context.Background(), tempDir)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
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
