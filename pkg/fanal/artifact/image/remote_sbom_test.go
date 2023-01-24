package image_test

import (
	"context"
	"testing"

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

type fakeImage struct {
	name        string
	repoDigests []string
	fakei.FakeImage
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
						BlobID: "sha256:8c90c68f385a8067778a200fd3e56e257d4d6dd563e519a7be65902ee0b6e861",
						BlobInfo: types.BlobInfo{
							SchemaVersion: types.BlobJSONSchemaVersion,
							OS: types.OS{
								Family: "alpine",
								Name:   "3.16.2",
							},
							PackageInfos: []types.PackageInfo{
								{
									Packages: []types.Package{
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
				ID:   "sha256:8c90c68f385a8067778a200fd3e56e257d4d6dd563e519a7be65902ee0b6e861",
				BlobIDs: []string{
					"sha256:8c90c68f385a8067778a200fd3e56e257d4d6dd563e519a7be65902ee0b6e861",
				},
			},
		},
		{
			name: "503",
			fields: fields{
				imageName: "test/image:10",
				repoDigests: []string{
					"test/image@sha256:unknown",
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

			fi := fakei.FakeImage{}
			fi.ConfigFileReturns(nil, nil)

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
