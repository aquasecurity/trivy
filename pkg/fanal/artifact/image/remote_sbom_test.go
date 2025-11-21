package image_test

import (
	"fmt"
	"net/url"
	"os"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	fakei "github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/cachetest"
	"github.com/aquasecurity/trivy/internal/registrytest"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	image2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/oci"
	"github.com/aquasecurity/trivy/pkg/rekortest"
	"github.com/aquasecurity/trivy/pkg/sbom"
)

func TestMain(m *testing.M) {
	log.InitLogger(false, true)
	os.Exit(m.Run())
}

type fakeImage struct {
	name        string
	repoDigests []string
	v1.Image
	ftypes.ImageExtension
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

func (f fakeImage) RepoTags() []string {
	return nil
}

func TestArtifact_InspectRekorAttestation(t *testing.T) {
	tests := []struct {
		name        string
		imageName   string
		repoDigests []string
		wantBlobs   []cachetest.WantBlob
		want        artifact.Reference
		wantErr     string
	}{
		{
			name:      "happy path",
			imageName: "test/image:10",
			repoDigests: []string{
				"test/image@sha256:782143e39f1e7a04e3f6da2d88b1c057e5657363c4f90679f3e8a071b7619e02",
			},
			wantBlobs: []cachetest.WantBlob{
				{
					ID: "sha256:066b9998617ffb7dfe0a3219ac5c3efc1008a6223606fcf474e7d5c965e4e8da",
					BlobInfo: ftypes.BlobInfo{
						SchemaVersion: ftypes.BlobJSONSchemaVersion,
						OS: ftypes.OS{
							Family: "alpine",
							Name:   "3.16.2",
						},
						PackageInfos: []ftypes.PackageInfo{
							{
								Packages: ftypes.Packages{
									{
										ID:      "musl@1.2.3-r0",
										Name:    "musl",
										Version: "1.2.3-r0",
										Identifier: ftypes.PkgIdentifier{
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
										Layer: ftypes.Layer{
											DiffID: "sha256:994393dc58e7931862558d06e46aa2bb17487044f670f310dffe1d24e4d1eec7",
										},
									},
								},
							},
						},
					},
				},
			},
			want: artifact.Reference{
				Name: "test/image:10",
				Type: ftypes.TypeCycloneDX,
				ID:   "sha256:066b9998617ffb7dfe0a3219ac5c3efc1008a6223606fcf474e7d5c965e4e8da",
				BlobIDs: []string{
					"sha256:066b9998617ffb7dfe0a3219ac5c3efc1008a6223606fcf474e7d5c965e4e8da",
				},
				ImageMetadata: artifact.ImageMetadata{
					ID: "sha256:9c6f0724472873bb50a2ae67a9e7adcb57673a183cea8b06eb778dca859181b5",
					DiffIDs: []string{
						"sha256:994393dc58e7931862558d06e46aa2bb17487044f670f310dffe1d24e4d1eec7",
					},
					RepoTags: []string{
						"alpine:3.16",
					},
					RepoDigests: []string{
						"alpine@sha256:bc41182d7ef5ffc53a40b044e725193bc10142a1243f395ee852a8d9730fc2ad",
					},
				},
			},
		},
		{
			name:      "attestation not found",
			imageName: "test/image:10",
			repoDigests: []string{
				"test/image@sha256:123456e39f1e7a04e3f6da2d88b1c057e5657363c4f90679f3e8a071b7619e02",
			},
			wantErr: "remote SBOM fetching error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := rekortest.NewServer(t)
			defer ts.Close()

			c := cachetest.NewCache(t, nil)

			fi := &fakei.FakeImage{}
			fi.ConfigFileReturns(&v1.ConfigFile{}, nil)

			img := &fakeImage{
				name:        tt.imageName,
				repoDigests: tt.repoDigests,
				Image:       fi,
			}
			a, err := image2.NewArtifact(img, c, artifact.Option{
				SBOMSources: []string{"rekor"},
				RekorURL:    ts.URL(),
			})
			require.NoError(t, err)

			got, err := a.Inspect(t.Context())
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			defer a.Clean(got)

			got.BOM = nil
			assert.Equal(t, tt.want, got)
			cachetest.AssertBlobs(t, c, tt.wantBlobs)
		})
	}
}

// Common test data for CycloneDX SBOM (used by OCI referrer tests)
var wantBlobsCycloneDX = []cachetest.WantBlob{
	{
		ID: "sha256:2171d8ccf798e94d09aca9c6abf15d28abd3236def1caa4a394b6f0a69c4266d",
		BlobInfo: ftypes.BlobInfo{
			SchemaVersion: ftypes.BlobJSONSchemaVersion,
			Applications: []ftypes.Application{
				{
					Type: ftypes.GoBinary,
					Packages: ftypes.Packages{
						{
							ID:      "github.com/opencontainers/go-digest@v1.0.0",
							Name:    "github.com/opencontainers/go-digest",
							Version: "v1.0.0",
							Identifier: ftypes.PkgIdentifier{
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
							Identifier: ftypes.PkgIdentifier{
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
}

func TestArtifact_InspectOCIReferrerSBOM(t *testing.T) {
	// Start a test registry with referrers support
	ts := registrytest.NewServer(t)
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	registryHost := u.Host

	tests := []struct {
		name      string
		setup     func(t *testing.T) (imageName string, repoDigests []string)
		wantType  ftypes.ArtifactType
		wantID    string
		wantBlobs []cachetest.WantBlob
	}{
		{
			name: "CycloneDX SBOM",
			setup: func(t *testing.T) (string, []string) {
				ref, subjectDesc := registrytest.PushRandomImage(t, registryHost, "test/cyclonedx", "latest")

				sbomContent, err := os.ReadFile("testdata/cyclonedx.json")
				require.NoError(t, err)

				registrytest.PushReferrer(t, registryHost, "test/cyclonedx", subjectDesc, oci.CycloneDXArtifactType, sbomContent)

				return ref.String(),
					[]string{fmt.Sprintf("%s/test/cyclonedx@%s", registryHost, subjectDesc.Digest.String())}
			},
			wantType:  ftypes.TypeCycloneDX,
			wantID:    "sha256:2171d8ccf798e94d09aca9c6abf15d28abd3236def1caa4a394b6f0a69c4266d",
			wantBlobs: wantBlobsCycloneDX,
		},
		{
			name: "Sigstore bundle",
			setup: func(t *testing.T) (string, []string) {
				ref, subjectDesc := registrytest.PushRandomImage(t, registryHost, "test/sigstore", "latest")

				bundleContent, err := os.ReadFile("testdata/sigstore-bundle.json")
				require.NoError(t, err)

				registrytest.PushReferrer(t, registryHost, "test/sigstore", subjectDesc, sbom.SigstoreBundleMediaType, bundleContent)

				return ref.String(),
					[]string{fmt.Sprintf("%s/test/sigstore@%s", registryHost, subjectDesc.Digest.String())}
			},
			wantType:  ftypes.TypeCycloneDX,
			wantID:    "sha256:2171d8ccf798e94d09aca9c6abf15d28abd3236def1caa4a394b6f0a69c4266d",
			wantBlobs: wantBlobsCycloneDX,
		},
		{
			name: "no referrers",
			setup: func(t *testing.T) (string, []string) {
				// Push image without any referrers
				ref, subjectDesc := registrytest.PushRandomImage(t, registryHost, "test/no-referrers", "latest")

				return ref.String(),
					[]string{fmt.Sprintf("%s/test/no-referrers@%s", registryHost, subjectDesc.Digest.String())}
			},
			// Falls back to normal image scanning when no referrers found
			wantType: ftypes.TypeContainerImage,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imageName, repoDigests := tt.setup(t)

			c := cachetest.NewCache(t, nil)

			fi := &fakei.FakeImage{}
			fi.ConfigFileReturns(&v1.ConfigFile{}, nil)

			img := &fakeImage{
				name:        imageName,
				repoDigests: repoDigests,
				Image:       fi,
			}
			a, err := image2.NewArtifact(img, c, artifact.Option{
				SBOMSources: []string{"oci"},
			})
			require.NoError(t, err)

			got, err := a.Inspect(t.Context())
			require.NoError(t, err)
			defer a.Clean(got)

			assert.Equal(t, tt.wantType, got.Type)
			if tt.wantID != "" {
				assert.Equal(t, tt.wantID, got.ID)
			}
			if tt.wantBlobs != nil {
				cachetest.AssertBlobs(t, c, tt.wantBlobs)
			}
		})
	}
}
