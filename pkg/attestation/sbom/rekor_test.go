package sbom

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	image2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	fakei "github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"
	"gotest.tools/assert"
)

func TestRekor_RetrieveSBOM(t *testing.T) {
	tests := []struct {
		name       string
		fields     fields
		digest     string
		searchFile string
		want       []string
		wantErr    string
	}{
		{
			name:       "happy path",
			digest:     "",
			searchFile: "testdata/rekor-search.json",
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
			searchFile: "testdata/rekor-search.json",
			artifactOpt: artifact.Option{
				SBOMSources: []string{"rekor"},
			},
			wantErr: "remote SBOM fetching error",
		},
	}

	log.InitLogger(false, true)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/index/retrieve":
					var params models.SearchIndex
					err := json.NewDecoder(r.Body).Decode(&params)
					require.NoError(t, err)

					if params.Hash == "sha256:bc41182d7ef5ffc53a40b044e725193bc10142a1243f395ee852a8d9730fc2ad" {
						http.ServeFile(w, r, tt.searchFile)
					} else {
						http.Error(w, "something wrong", http.StatusInternalServerError)
					}
				case "/api/v1/log/entries/retrieve":
					var params models.SearchLogQuery
					err := json.NewDecoder(r.Body).Decode(&params)
					require.NoError(t, err)

					if slices.Equal(
						params.EntryUUIDs,
						[]string{
							"392f8ecba72f4326eb624a7403756250b5f2ad58842a99d1653cd6f147f4ce9eda2da350bd908a55",
							"392f8ecba72f4326414eaca77bd19bf5f378725d7fd79309605a81b69cc0101f5cd3119d0a216523",
						},
					) {
						http.ServeFile(w, r, "testdata/log-entries.json")
					} else if slices.Equal(
						params.EntryUUIDs,
						[]string{"392f8ecba72f4326eb624a7403756250b5f2ad58842a99d1653cd6f147f4ce9eda2da350bd908a55"},
					) {
						http.ServeFile(w, r, "testdata/log-entries-no-attestation.json")
					} else {
						http.Error(w, "something wrong", http.StatusInternalServerError)
					}
				}
				return
			}))
			defer ts.Close()

			// Set the testing URL
			tt.artifactOpt.RekorURL = ts.URL

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
