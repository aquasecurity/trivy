package dbtest

import (
	"archive/tar"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	fakei "github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/asset"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

const defaultMediaType = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"

type fakeLayer struct {
	v1.Layer
}

func (f fakeLayer) MediaType() (types.MediaType, error) {
	return f.Layer.MediaType()
}

func NewFakeLayer(t *testing.T, input string, mediaType types.MediaType) v1.Layer {
	layer, err := tarball.LayerFromFile(input, tarball.WithMediaType(mediaType))
	require.NoError(t, err)

	return fakeLayer{layer}
}

type FakeDBOptions struct {
	MediaType types.MediaType
}

func NewFakeDB(t *testing.T, dbPath string, opts FakeDBOptions) *asset.OCI {
	mediaType := lo.Ternary(opts.MediaType != "", opts.MediaType, defaultMediaType)
	img := new(fakei.FakeImage)
	img.LayersReturns([]v1.Layer{NewFakeLayer(t, dbPath, mediaType)}, nil)
	img.ManifestReturns(&v1.Manifest{
		Layers: []v1.Descriptor{
			{
				MediaType: mediaType,
				Size:      100,
				Digest: v1.Hash{
					Algorithm: "sha256",
					Hex:       "aec482bc254b5dd025d3eaf5bb35997d3dba783e394e8f91d5a415963151bfb8",
				},
				Annotations: map[string]string{
					"org.opencontainers.image.title": "db.tar.gz",
				},
			},
		},
	}, nil)

	// Mock OCI artifact
	assetOpts := asset.Options{
		MediaType: defaultMediaType,
		RegistryOptions: ftypes.RegistryOptions{
			Insecure: false,
		},
	}
	return asset.NewOCI("dummy", assetOpts, asset.WithImage(img))
}

func ArchiveDir(t *testing.T, dir string) string {
	tmpDBPath := filepath.Join(t.TempDir(), "db.tar")
	f, err := os.Create(tmpDBPath)
	require.NoError(t, err)
	defer f.Close()

	tr := tar.NewWriter(f)
	defer tr.Close()

	err = tr.AddFS(os.DirFS(dir))
	require.NoError(t, err)

	return tmpDBPath
}
