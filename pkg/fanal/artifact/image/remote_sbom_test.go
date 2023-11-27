package image_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	fakei "github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	image2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/rekortest"
)

func TestMain(m *testing.M) {
	log.InitLogger(false, true)
	os.Exit(m.Run())
}

type fakeImage struct {
	name        string
	repoDigests []string
	*fakei.FakeImage
	types.ImageExtension
}

func (f fakeImage) ID() (string, error) {
	return "", nil
}

func (f fakeImage) Name() string {
	return f.name
}

func (f fakeImage) RepoDigests() []string {
	return f.repoDigests
}

func TestArtifact_InspectRekorAttestation(t *testing.T) {
	type fields struct {
		imageName   string
		repoDigests []string
	}
	tests := []struct {
		name                string
		fields              fields
		artifactOpt         artifact.Option
		putBlobExpectations []cache.ArtifactCachePutBlobExpectation
		want                types.ArtifactReference
		wantErr             string
	}{
		{
			name: "happy path",
			fields: fields{
				imageName: "test/image:10",
				repoDigests: []string{
					"test/image@sha256:782143e39f1e7a04e3f6da2d88b1c057e5657363c4f90679f3e8a071b7619e02",
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:9c23872047046e145f49fb5533b63ace0cbf819f5b68e33f69f4e9bbab4c517e",
						BlobInfo: types.BlobInfo{
							SchemaVersion: types.BlobJSONSchemaVersion,
							OS: types.OS{
								Family: "alpine",
								Name:   "3.16.2",
							},
							PackageInfos: []types.PackageInfo{
								{
									Packages: types.Packages{
										{
											Name:       "musl",
											Version:    "1.2.3-r0",
											SrcName:    "musl",
											SrcVersion: "1.2.3-r0",
											Licenses:   []string{"MIT"},
											Ref:        "pkg:apk/alpine/musl@1.2.3-r0?distro=3.16.2",
											Layer: types.Layer{
												DiffID: "sha256:994393dc58e7931862558d06e46aa2bb17487044f670f310dffe1d24e4d1eec7",
											},
										},
									},
								},
							},
						},
					},
					Returns: cache.ArtifactCachePutBlobReturns{},
				},
			},
			artifactOpt: artifact.Option{
				SBOMSources: []string{"rekor"},
			},
			want: types.ArtifactReference{
				Name: "test/image:10",
				Type: types.ArtifactCycloneDX,
				ID:   "sha256:9c23872047046e145f49fb5533b63ace0cbf819f5b68e33f69f4e9bbab4c517e",
				BlobIDs: []string{
					"sha256:9c23872047046e145f49fb5533b63ace0cbf819f5b68e33f69f4e9bbab4c517e",
				},
			},
		},
		{
			name: "error",
			fields: fields{
				imageName: "test/image:10",
				repoDigests: []string{
					"test/image@sha256:123456e39f1e7a04e3f6da2d88b1c057e5657363c4f90679f3e8a071b7619e02",
				},
			},
			artifactOpt: artifact.Option{
				SBOMSources: []string{"rekor"},
			},
			wantErr: "remote SBOM fetching error",
		},
	}

	require.NoError(t, log.InitLogger(false, true))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := rekortest.NewServer(t)
			defer ts.Close()

			// Set the testing URL
			tt.artifactOpt.RekorURL = ts.URL()

			mockCache := new(cache.MockArtifactCache)
			mockCache.ApplyPutBlobExpectations(tt.putBlobExpectations)

			fi := &fakei.FakeImage{}
			fi.ConfigFileReturns(&v1.ConfigFile{}, nil)

			img := &fakeImage{
				name:        tt.fields.imageName,
				repoDigests: tt.fields.repoDigests,
				FakeImage:   fi,
			}
			a, err := image2.NewArtifact(img, mockCache, tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err, tt.name)
			got.CycloneDX = nil
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestArtifact_inspectOCIReferrerSBOM(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2":
			_, err := w.Write([]byte("ok"))
			require.NoError(t, err)
		case "/v2/test/image/referrers/sha256:782143e39f1e7a04e3f6da2d88b1c057e5657363c4f90679f3e8a071b7619e02":
			http.ServeFile(w, r, "testdata/index.json")
		case "/v2/test/image/manifests/sha256:37c89af4907fa0af078aeba12d6f18dc0c63937c010030baaaa88e958f0719a5":
			http.ServeFile(w, r, "testdata/manifest.json")
		case "/v2/test/image/blobs/sha256:9e05dda2a2dcdd526c9204be8645ae48742861c27f093bf496a6397834acecf2":
			http.ServeFile(w, r, "testdata/cyclonedx.json")
		}
		return
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	registry := u.Host

	type fields struct {
		imageName   string
		repoDigests []string
	}

	tests := []struct {
		name                string
		fields              fields
		artifactOpt         artifact.Option
		putBlobExpectations []cache.ArtifactCachePutBlobExpectation
		want                types.ArtifactReference
		wantErr             string
	}{
		{
			name: "happy path",
			fields: fields{
				imageName: registry + "/test/image:10",
				repoDigests: []string{
					registry + "/test/image@sha256:782143e39f1e7a04e3f6da2d88b1c057e5657363c4f90679f3e8a071b7619e02",
				},
			},
			artifactOpt: artifact.Option{
				SBOMSources: []string{"oci"},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:d07a1894bfd283b4ac26682ab48f12ad22cdc4fef9cf8b4c09056f631d3667a5",
						BlobInfo: types.BlobInfo{
							SchemaVersion: types.BlobJSONSchemaVersion,
							Applications: []types.Application{
								{
									Type: types.GoBinary,
									Libraries: types.Packages{
										{
											Name:    "github.com/opencontainers/go-digest",
											Version: "v1.0.0",
											Ref:     "pkg:golang/github.com/opencontainers/go-digest@v1.0.0",
										},
										{
											Name:    "golang.org/x/sync",
											Version: "v0.1.0",
											Ref:     "pkg:golang/golang.org/x/sync@v0.1.0",
										},
									},
								},
							},
						},
					},
				},
			},
			want: types.ArtifactReference{
				Name: registry + "/test/image:10",
				Type: types.ArtifactCycloneDX,
				ID:   "sha256:d07a1894bfd283b4ac26682ab48f12ad22cdc4fef9cf8b4c09056f631d3667a5",
				BlobIDs: []string{
					"sha256:d07a1894bfd283b4ac26682ab48f12ad22cdc4fef9cf8b4c09056f631d3667a5",
				},
			},
		},
		{
			name: "404",
			fields: fields{
				imageName: registry + "/test/image:unknown",
				repoDigests: []string{
					registry + "/test/image@sha256:123456e39f1e7a04e3f6da2d88b1c057e5657363c4f90679f3e8a071b7619e02",
				},
			},
			artifactOpt: artifact.Option{
				SBOMSources: []string{"oci"},
			},
			wantErr: "unable to get manifest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCache := new(cache.MockArtifactCache)
			mockCache.ApplyPutBlobExpectations(tt.putBlobExpectations)

			fi := &fakei.FakeImage{}
			fi.ConfigFileReturns(&v1.ConfigFile{}, nil)

			img := &fakeImage{
				name:        tt.fields.imageName,
				repoDigests: tt.fields.repoDigests,
				FakeImage:   fi,
			}
			a, err := image2.NewArtifact(img, mockCache, tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err, tt.name)
			got.CycloneDX = nil
			assert.Equal(t, tt.want, got)
		})
	}
}
