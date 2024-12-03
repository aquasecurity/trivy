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
	typesv1 "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	image2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
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
		want                artifact.Reference
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
						BlobID: "sha256:066b9998617ffb7dfe0a3219ac5c3efc1008a6223606fcf474e7d5c965e4e8da",
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
											ID:      "musl@1.2.3-r0",
											Name:    "musl",
											Version: "1.2.3-r0",
											Identifier: types.PkgIdentifier{
												PURL: &packageurl.PackageURL{
													Type:      packageurl.TypeApk,
													Namespace: "alpine",
													Name:      "musl",
													Version:   "1.2.3-r0",
													Qualifiers: packageurl.Qualifiers{
														{
															Key:   "distro",
															Value: "3.16.2",
														},
													},
												},
												BOMRef: "pkg:apk/alpine/musl@1.2.3-r0?distro=3.16.2",
											},
											SrcName:    "musl",
											SrcVersion: "1.2.3-r0",
											Licenses:   []string{"MIT"},
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
			want: artifact.Reference{
				Name: "test/image:10",
				Type: artifact.TypeCycloneDX,
				ID:   "sha256:066b9998617ffb7dfe0a3219ac5c3efc1008a6223606fcf474e7d5c965e4e8da",
				BlobIDs: []string{
					"sha256:066b9998617ffb7dfe0a3219ac5c3efc1008a6223606fcf474e7d5c965e4e8da",
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

	log.InitLogger(false, true)
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
			got.BOM = nil
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestArtifact_inspectOCIReferrerSBOM(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2":
			_, err := w.Write([]byte("ok"))
			assert.NoError(t, err)
		case "/v2/test/image/referrers/sha256:782143e39f1e7a04e3f6da2d88b1c057e5657363c4f90679f3e8a071b7619e02":
			w.Header().Set("Content-Type", string(typesv1.OCIImageIndex))
			http.ServeFile(w, r, "testdata/index.json")
		case "/v2/test/image/manifests/sha256:37c89af4907fa0af078aeba12d6f18dc0c63937c010030baaaa88e958f0719a5":
			http.ServeFile(w, r, "testdata/manifest.json")
		case "/v2/test/image/blobs/sha256:9e05dda2a2dcdd526c9204be8645ae48742861c27f093bf496a6397834acecf2":
			http.ServeFile(w, r, "testdata/cyclonedx.json")
		}
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
		want                artifact.Reference
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
						BlobID: "sha256:a06ed679a3289fba254040e1ce8f3467fadcc454ee3d0d4720f6978065f56684",
						BlobInfo: types.BlobInfo{
							SchemaVersion: types.BlobJSONSchemaVersion,
							Applications: []types.Application{
								{
									Type: types.GoBinary,
									Packages: types.Packages{
										{
											ID:      "github.com/opencontainers/go-digest@v1.0.0",
											Name:    "github.com/opencontainers/go-digest",
											Version: "v1.0.0",
											Identifier: types.PkgIdentifier{
												PURL: &packageurl.PackageURL{
													Type:      packageurl.TypeGolang,
													Namespace: "github.com/opencontainers",
													Name:      "go-digest",
													Version:   "v1.0.0",
												},
												BOMRef: "pkg:golang/github.com/opencontainers/go-digest@v1.0.0",
											},
										},
										{
											ID:      "golang.org/x/sync@v0.1.0",
											Name:    "golang.org/x/sync",
											Version: "v0.1.0",
											Identifier: types.PkgIdentifier{
												PURL: &packageurl.PackageURL{
													Type:      packageurl.TypeGolang,
													Namespace: "golang.org/x",
													Name:      "sync",
													Version:   "v0.1.0",
												},
												BOMRef: "pkg:golang/golang.org/x/sync@v0.1.0",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: artifact.Reference{
				Name: registry + "/test/image:10",
				Type: artifact.TypeCycloneDX,
				ID:   "sha256:a06ed679a3289fba254040e1ce8f3467fadcc454ee3d0d4720f6978065f56684",
				BlobIDs: []string{
					"sha256:a06ed679a3289fba254040e1ce8f3467fadcc454ee3d0d4720f6978065f56684",
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
			got.BOM = nil
			assert.Equal(t, tt.want, got)
		})
	}
}
