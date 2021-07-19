package policy_test

import (
	"context"
	"encoding/json"
	"fmt"
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

	"github.com/aquasecurity/trivy/pkg/policy"
	"github.com/aquasecurity/trivy/pkg/utils"
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

	return fakeLayer{layer}
}

func TestClient_LoadBuiltinPolicies(t *testing.T) {
	tests := []struct {
		name     string
		cacheDir string
		want     []string
		wantErr  string
	}{
		{
			name:     "happy path",
			cacheDir: "testdata/happy",
			want: []string{
				"testdata/happy/policy/content/kubernetes",
				"testdata/happy/policy/content/docker",
			},
		},
		{
			name:     "empty roots",
			cacheDir: "testdata/empty",
			want: []string{
				"testdata/empty/policy/content",
			},
		},
		{
			name:     "broken manifest",
			cacheDir: "testdata/broken",
			want:     []string{},
			wantErr:  "json decode error",
		},
		{
			name:     "no such file",
			cacheDir: "testdata/unknown",
			want:     []string{},
			wantErr:  "manifest file open error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			utils.SetCacheDir(tt.cacheDir)

			img := new(fakei.FakeImage)
			c, err := policy.NewClient(policy.WithImage(img))
			require.NoError(t, err)

			got, err := c.LoadBuiltinPolicies()
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClient_NeedsUpdate(t *testing.T) {
	type digestReturns struct {
		h   v1.Hash
		err error
	}
	tests := []struct {
		name          string
		clock         clock.Clock
		digestReturns digestReturns
		metadata      interface{}
		want          bool
		wantErr       bool
	}{
		{
			name:  "recent download",
			clock: fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			digestReturns: digestReturns{
				h: v1.Hash{Algorithm: "sha256", Hex: "01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d"},
			},
			metadata: policy.Metadata{
				Digest:           `sha256:922e50f14ab484f11ae65540c3d2d76009020213f1027d4331d31141575e5414`,
				LastDownloadedAt: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			want: false,
		},
		{
			name:  "same digest",
			clock: fake.NewFakeClock(time.Date(2021, 1, 2, 1, 0, 0, 0, time.UTC)),
			digestReturns: digestReturns{
				h: v1.Hash{Algorithm: "sha256", Hex: "01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d"},
			},
			metadata: policy.Metadata{
				Digest:           `sha256:01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d`,
				LastDownloadedAt: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			want: false,
		},
		{
			name:  "different digest",
			clock: fake.NewFakeClock(time.Date(2021, 1, 2, 1, 0, 0, 0, time.UTC)),
			digestReturns: digestReturns{
				h: v1.Hash{Algorithm: "sha256", Hex: "01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d"},
			},
			metadata: policy.Metadata{
				Digest:           `sha256:922e50f14ab484f11ae65540c3d2d76009020213f1027d4331d31141575e5414`,
				LastDownloadedAt: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			want: true,
		},
		{
			name:  "sad: Digest returns  an error",
			clock: fake.NewFakeClock(time.Date(2021, 1, 2, 1, 0, 0, 0, time.UTC)),
			digestReturns: digestReturns{
				err: fmt.Errorf("error"),
			},
			metadata: policy.Metadata{
				Digest:           `sha256:922e50f14ab484f11ae65540c3d2d76009020213f1027d4331d31141575e5414`,
				LastDownloadedAt: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			want:    false,
			wantErr: true,
		},
		{
			name:  "sad: non-existent metadata",
			clock: fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			want:  true,
		},
		{
			name:     "sad: broken metadata",
			clock:    fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			metadata: `"foo"`,
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up a temporary directory
			tmpDir := t.TempDir()
			utils.SetCacheDir(tmpDir)

			// Mock image
			img := new(fakei.FakeImage)
			img.DigestReturns(tt.digestReturns.h, tt.digestReturns.err)

			// Create a policy directory
			err := os.MkdirAll(filepath.Join(tmpDir, "policy"), os.ModePerm)
			require.NoError(t, err)

			if tt.metadata != nil {
				b, err := json.Marshal(tt.metadata)
				require.NoError(t, err)

				// Write a metadata file
				metadataPath := filepath.Join(tmpDir, "policy", "metadata.json")
				err = os.WriteFile(metadataPath, b, os.ModePerm)
				require.NoError(t, err)
			}

			// Assert results
			c, err := policy.NewClient(policy.WithImage(img), policy.WithClock(tt.clock))
			require.NoError(t, err)

			got, err := c.NeedsUpdate()
			assert.Equal(t, tt.wantErr, err != nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClient_DownloadBuiltinPolicies(t *testing.T) {
	layer := newFakeLayer(t)

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
		clock         clock.Clock
		layersReturns layersReturns
		digestReturns digestReturns
		want          *policy.Metadata
		wantErr       string
	}{
		{
			name:  "happy path",
			clock: fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			layersReturns: layersReturns{
				layers: []v1.Layer{layer},
			},
			digestReturns: digestReturns{
				h: v1.Hash{Algorithm: "sha256", Hex: "01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d"},
			},
			want: &policy.Metadata{
				Digest:           "sha256:01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d",
				LastDownloadedAt: time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC),
			},
		},
		{
			name:  "sad: two layers",
			clock: fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			layersReturns: layersReturns{
				layers: []v1.Layer{layer, layer},
			},
			want: &policy.Metadata{
				Digest:           "sha256:01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d",
				LastDownloadedAt: time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC),
			},
			wantErr: "OPA bundle must be a single layer",
		},
		{
			name:  "sad: Layers returns an error",
			clock: fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			layersReturns: layersReturns{
				err: fmt.Errorf("error"),
			},
			digestReturns: digestReturns{
				h: v1.Hash{Algorithm: "sha256", Hex: "01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d"},
			},
			want: &policy.Metadata{
				Digest:           "sha256:01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d",
				LastDownloadedAt: time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC),
			},
			wantErr: "OCI layer error",
		},
		{
			name:  "sad: Digest returns an error",
			clock: fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			layersReturns: layersReturns{
				layers: []v1.Layer{layer},
			},
			digestReturns: digestReturns{
				err: fmt.Errorf("error"),
			},
			want: &policy.Metadata{
				Digest:           "sha256:01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d",
				LastDownloadedAt: time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC),
			},
			wantErr: "digest error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			utils.SetCacheDir(tempDir)

			// Mock image
			img := new(fakei.FakeImage)
			img.DigestReturns(tt.digestReturns.h, tt.digestReturns.err)
			img.LayersReturns(tt.layersReturns.layers, tt.layersReturns.err)

			c, err := policy.NewClient(policy.WithClock(tt.clock), policy.WithImage(img))
			require.NoError(t, err)

			err = c.DownloadBuiltinPolicies(context.Background())
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)

			// Assert metadata.json
			metadata := filepath.Join(tempDir, "policy", "metadata.json")
			b, err := os.ReadFile(metadata)
			require.NoError(t, err)

			got := new(policy.Metadata)
			err = json.Unmarshal(b, got)
			require.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}
