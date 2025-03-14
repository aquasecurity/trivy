package operation

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	fakei "github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/clock"
	fake "k8s.io/utils/clock/testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/oci"
	"github.com/aquasecurity/trivy/pkg/policy"
)

type fakeLayer struct {
	v1.Layer
}

func (f fakeLayer) MediaType() (types.MediaType, error) {
	return "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip", nil
}

func newFakeLayer(t *testing.T) v1.Layer {
	layer, err := tarball.LayerFromFile("testdata/bundle.tar.gz")
	require.NoError(t, err)
	require.NotNil(t, layer)

	return fakeLayer{layer}
}

func TestInitBuiltinChecks(t *testing.T) {
	type digestReturns struct {
		h   v1.Hash
		err error
	}
	type layersReturns struct {
		layers []v1.Layer
		err    error
	}
	tests := []struct {
		name          string
		metadata      any
		checkDir      string
		skipUpdate    bool
		wantErr       string
		layersReturns layersReturns
		digestReturns digestReturns
		want          *policy.Metadata
		clock         clock.Clock
	}{
		{
			name: "happy path - no need to update",
			digestReturns: digestReturns{
				h: v1.Hash{
					Algorithm: "sha256",
					Hex:       "01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d",
				},
			},
			checkDir: filepath.Join("policy"),
			clock:    fake.NewFakeClock(time.Date(1992, 1, 1, 1, 0, 0, 0, time.UTC)),
			metadata: policy.Metadata{
				Digest:       `sha256:922e50f14ab484f11ae65540c3d2d76009020213f1027d4331d31141575e5414`,
				DownloadedAt: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			skipUpdate: false,
		},
		{
			name:       "skip update flag set with no existing cache to fallback to",
			skipUpdate: true,
			checkDir:   filepath.Join("policy"),
			wantErr:    "not found falling back to embedded checks...",
		},
		{
			name:       "skip update flag set with existing cache to fallback to",
			skipUpdate: true,
			checkDir:   filepath.Join("policy", "content"),
			clock:      fake.NewFakeClock(time.Date(1992, 1, 1, 1, 0, 0, 0, time.UTC)),
			metadata: policy.Metadata{
				Digest:       `sha256:922e50f14ab484f11ae65540c3d2d76009020213f1027d4331d31141575e5414`,
				DownloadedAt: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		{
			name: "needs update returns an error",
			digestReturns: digestReturns{
				err: errors.New("digest error"),
			},
			metadata: policy.Metadata{
				Digest:       `sha256:922e50f14ab484f11ae65540c3d2d76009020213f1027d4331d31141575e5414`,
				DownloadedAt: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			checkDir: filepath.Join("policy"),
			clock:    fake.NewFakeClock(time.Date(3000, 1, 1, 1, 0, 0, 0, time.UTC)),
			wantErr:  "unable to check if built-in policies need to be updated",
		},
		{
			name:  "sad: download builtin checks returns an error",
			clock: fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			layersReturns: layersReturns{
				layers: []v1.Layer{newFakeLayer(t)},
			},
			digestReturns: digestReturns{
				err: errors.New("error"),
			},
			want: &policy.Metadata{
				Digest:       "sha256:01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d",
				DownloadedAt: time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC),
			},
			wantErr: "digest error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			// Set up a temporary directory
			tmpDir := t.TempDir()

			// Create a check directory
			err := os.MkdirAll(filepath.Join(tmpDir, tt.checkDir), os.ModePerm)
			require.NoError(t, err)

			if tt.metadata != nil {
				b, err := json.Marshal(tt.metadata)
				require.NoError(t, err)

				// Write a metadata file
				metadataPath := filepath.Join(tmpDir, "policy", "metadata.json")
				err = os.WriteFile(metadataPath, b, os.ModePerm)
				require.NoError(t, err)
			}

			// Mock image
			img := new(fakei.FakeImage)
			img.LayersReturns([]v1.Layer{newFakeLayer(t)}, nil)
			img.DigestReturns(tt.digestReturns.h, tt.digestReturns.err)
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

			// Mock OCI artifact
			art := oci.NewArtifact("repo", ftypes.RegistryOptions{}, oci.WithImage(img))
			c, err := policy.NewClient(tmpDir, true, "", policy.WithOCIArtifact(art), policy.WithClock(tt.clock))
			require.NoError(t, err)

			got, err := InitBuiltinChecks(ctx, c, tt.skipUpdate, ftypes.RegistryOptions{})

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.NotEmpty(t, got)
		})
	}
}
