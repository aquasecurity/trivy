package policy_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	fakei "github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/samber/lo"
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

type brokenLayer struct {
	v1.Layer
}

func (b brokenLayer) MediaType() (types.MediaType, error) {
	return "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip", nil
}

func (b brokenLayer) Compressed() (io.ReadCloser, error) {
	return nil, errors.New("compressed error")
}

func newBrokenLayer(t *testing.T) v1.Layer {
	layer, err := tarball.LayerFromFile("testdata/bundle.tar.gz")
	require.NoError(t, err)

	return brokenLayer{layer}
}

func TestClient_LoadBuiltinChecks(t *testing.T) {
	tests := []struct {
		name     string
		cacheDir string
		want     string
		wantErr  string
	}{
		{
			name:     "happy path",
			cacheDir: "testdata/happy",
			want:     filepath.Join("testdata", "happy", "policy", "content"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock image
			img := new(fakei.FakeImage)
			img.LayersReturns([]v1.Layer{newFakeLayer(t)}, nil)
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
			c, err := policy.NewClient(tt.cacheDir, true, "", policy.WithOCIArtifact(art))
			require.NoError(t, err)

			got := c.BuiltinChecksPath()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

type annotations = map[string]string

func TestClient_NeedsUpdate(t *testing.T) {
	type digestReturns struct {
		h   v1.Hash
		err error
	}

	imageDigest := digestReturns{
		h: v1.Hash{
			Algorithm: "sha256",
			Hex:       "01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d",
		},
	}

	usedBundleVersion := fmt.Sprintf("%d.0.0", policy.BundleVersion)

	tests := []struct {
		name          string
		clock         clock.Clock
		digestReturns digestReturns
		metadata      any
		want          bool
		wantMetadata  *policy.Metadata
		wantErr       bool
	}{
		{
			name:          "recent download",
			clock:         fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			digestReturns: imageDigest,
			metadata: policy.Metadata{
				Digest:       `sha256:922e50f14ab484f11ae65540c3d2d76009020213f1027d4331d31141575e5414`,
				DownloadedAt: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
				MajorVersion: lo.ToPtr(policy.BundleVersion),
			},
			want: false,
		},
		{
			name:          "same digest",
			clock:         fake.NewFakeClock(time.Date(2021, 1, 2, 1, 0, 0, 0, time.UTC)),
			digestReturns: imageDigest,
			metadata: policy.Metadata{
				Digest:       `sha256:01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d`,
				DownloadedAt: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
				MajorVersion: lo.ToPtr(policy.BundleVersion),
			},
			want: false,
			wantMetadata: &policy.Metadata{
				Digest:       `sha256:01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d`,
				DownloadedAt: time.Date(2021, 1, 2, 1, 0, 0, 0, time.UTC),
				MajorVersion: lo.ToPtr(policy.BundleVersion),
			},
		},
		{
			name:          "different digest",
			clock:         fake.NewFakeClock(time.Date(2021, 1, 2, 1, 0, 0, 0, time.UTC)),
			digestReturns: imageDigest,
			metadata: policy.Metadata{
				Digest:       `sha256:922e50f14ab484f11ae65540c3d2d76009020213f1027d4331d31141575e5414`,
				DownloadedAt: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
				MajorVersion: lo.ToPtr(policy.BundleVersion),
			},
			want: true,
		},
		{
			name:  "sad: Digest returns  an error",
			clock: fake.NewFakeClock(time.Date(2021, 1, 2, 1, 0, 0, 0, time.UTC)),
			digestReturns: digestReturns{
				err: errors.New("error"),
			},
			metadata: policy.Metadata{
				Digest:       `sha256:922e50f14ab484f11ae65540c3d2d76009020213f1027d4331d31141575e5414`,
				DownloadedAt: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
				MajorVersion: lo.ToPtr(policy.BundleVersion),
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
		{
			name:          "old metadata without version",
			clock:         fake.NewFakeClock(time.Date(2021, 1, 2, 1, 0, 0, 0, time.UTC)),
			digestReturns: imageDigest,
			metadata: policy.Metadata{
				Digest:       `sha256:01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d`,
				DownloadedAt: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			want: true,
		},
		{
			name:          "version mismatched",
			clock:         fake.NewFakeClock(time.Date(2021, 1, 2, 1, 0, 0, 0, time.UTC)),
			digestReturns: imageDigest,
			metadata: policy.Metadata{
				Digest:       `sha256:01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d`,
				DownloadedAt: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
				MajorVersion: lo.ToPtr(1),
			},
			want: true,
		},
		{
			name:          "version mismatched but custom build",
			clock:         fake.NewFakeClock(time.Date(2021, 1, 2, 1, 0, 0, 0, time.UTC)),
			digestReturns: imageDigest,
			metadata: policy.Metadata{
				Digest:       `sha256:01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d`,
				DownloadedAt: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
				CustomBuild:  true,
				MajorVersion: lo.ToPtr(1),
			},
			want: false,
			wantMetadata: &policy.Metadata{
				Digest:       `sha256:01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d`,
				DownloadedAt: time.Date(2021, 1, 2, 1, 0, 0, 0, time.UTC),
				CustomBuild:  true,
				MajorVersion: lo.ToPtr(1),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up a temporary directory
			tmpDir := t.TempDir()

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
				Annotations: annotations{
					policy.VersionAnnotationKey: usedBundleVersion,
				},
			}, nil)

			// Create a check directory
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

			art := oci.NewArtifact("repo", ftypes.RegistryOptions{}, oci.WithImage(img))
			c, err := policy.NewClient(tmpDir, true, "", policy.WithOCIArtifact(art), policy.WithClock(tt.clock))
			require.NoError(t, err)

			// Assert results
			got, err := c.NeedsUpdate(t.Context(), ftypes.RegistryOptions{})
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.Equal(t, tt.want, got)

			// Verify that metadata has been updated correctly
			if metadata, ok := tt.metadata.(policy.Metadata); ok {
				metadataPath := filepath.Join(tmpDir, "policy", "metadata.json")
				b, err := os.ReadFile(metadataPath)
				require.NoError(t, err)

				var want policy.Metadata
				err = json.Unmarshal(b, &want)
				require.NoError(t, err)

				if tt.wantMetadata == nil {
					// Metadata has not been changed
					tt.wantMetadata = lo.ToPtr(metadata)
				}

				assert.Equal(t, tt.wantMetadata, &want)
			}
		})
	}
}

func TestClient_DownloadBuiltinChecks(t *testing.T) {
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
		annotations   annotations
		want          *policy.Metadata
		wantErr       string
	}{
		{
			name:  "happy path",
			clock: fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			layersReturns: layersReturns{
				layers: []v1.Layer{newFakeLayer(t)},
			},
			digestReturns: digestReturns{
				h: v1.Hash{
					Algorithm: "sha256",
					Hex:       "01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d",
				},
			},
			want: &policy.Metadata{
				Digest:       "sha256:01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d",
				DownloadedAt: time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC),
				MajorVersion: lo.ToPtr(policy.BundleVersion),
			},
		},
		{
			name:  "sad: broken layer",
			clock: fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			layersReturns: layersReturns{
				layers: []v1.Layer{newBrokenLayer(t)},
			},
			digestReturns: digestReturns{
				h: v1.Hash{
					Algorithm: "sha256",
					Hex:       "01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d",
				},
			},
			wantErr: "compressed error",
		},
		{
			name:  "sad: Digest returns an error",
			clock: fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			layersReturns: layersReturns{
				layers: []v1.Layer{newFakeLayer(t)},
			},
			digestReturns: digestReturns{
				err: errors.New("error"),
			},
			wantErr: "digest error",
		},
		{
			name:  "custom bundle",
			clock: fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			layersReturns: layersReturns{
				layers: []v1.Layer{newFakeLayer(t)},
			},
			digestReturns: digestReturns{
				h: v1.Hash{
					Algorithm: "sha256",
					Hex:       "01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d",
				},
			},
			annotations: annotations{},
			want: &policy.Metadata{
				Digest:       "sha256:01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d",
				DownloadedAt: time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC),
				MajorVersion: lo.ToPtr(0),
				CustomBuild:  true,
			},
		},
		{
			name:  "invalid version is treated as a custom build",
			clock: fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			layersReturns: layersReturns{
				layers: []v1.Layer{newFakeLayer(t)},
			},
			digestReturns: digestReturns{
				h: v1.Hash{
					Algorithm: "sha256",
					Hex:       "01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d",
				},
			},
			annotations: annotations{
				policy.VersionAnnotationKey: "dev",
			},
			want: &policy.Metadata{
				Digest:       "sha256:01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d",
				DownloadedAt: time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC),
				MajorVersion: lo.ToPtr(0),
				CustomBuild:  true,
			},
		},
		{
			name:  "nightly build",
			clock: fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			layersReturns: layersReturns{
				layers: []v1.Layer{newFakeLayer(t)},
			},
			digestReturns: digestReturns{
				h: v1.Hash{
					Algorithm: "sha256",
					Hex:       "01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d",
				},
			},
			annotations: annotations{
				policy.VersionAnnotationKey: "2.0.1-nightly.20260129",
			},
			want: &policy.Metadata{
				Digest:       "sha256:01e033e78bd8a59fa4f4577215e7da06c05e1152526094d8d79d2aa06e98cb9d",
				DownloadedAt: time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC),
				MajorVersion: lo.ToPtr(2),
				CustomBuild:  false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			// Mock image
			img := new(fakei.FakeImage)
			img.DigestReturns(tt.digestReturns.h, tt.digestReturns.err)
			img.LayersReturns(tt.layersReturns.layers, tt.layersReturns.err)

			manifest := &v1.Manifest{
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
				Annotations: make(map[string]string),
			}

			if tt.annotations != nil {
				maps.Copy(manifest.Annotations, tt.annotations)
			} else {
				// Set default version
				manifest.Annotations[policy.VersionAnnotationKey] = fmt.Sprintf("%d.0.0", policy.BundleVersion)
			}

			img.ManifestReturns(manifest, nil)

			// Mock OCI artifact
			art := oci.NewArtifact("repo", ftypes.RegistryOptions{}, oci.WithImage(img))
			c, err := policy.NewClient(tempDir, true, "", policy.WithClock(tt.clock), policy.WithOCIArtifact(art))
			require.NoError(t, err)

			err = c.DownloadBuiltinChecks(t.Context(), ftypes.RegistryOptions{})
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

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

func TestClient_Clear(t *testing.T) {
	cacheDir := t.TempDir()
	err := os.MkdirAll(filepath.Join(cacheDir, "policy"), 0o755)
	require.NoError(t, err)

	c, err := policy.NewClient(cacheDir, true, "")
	require.NoError(t, err)
	require.NoError(t, c.Clear())
}
