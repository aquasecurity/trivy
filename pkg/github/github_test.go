package github

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v33/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/xerrors"
)

type MockRepository struct {
	mock.Mock
}

func (_m *MockRepository) ListReleases(ctx context.Context, opt *github.ListOptions) (
	[]*github.RepositoryRelease, *github.Response, error) {
	ret := _m.Called(ctx, opt)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return nil, nil, ret.Error(2)
	}
	releases, ok := ret0.([]*github.RepositoryRelease)
	if !ok {
		return nil, nil, ret.Error(2)
	}
	return releases, nil, ret.Error(2)
}

func (_m *MockRepository) DownloadAsset(ctx context.Context, id int64) (io.ReadCloser, string, error) {
	ret := _m.Called(ctx, id)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return nil, ret.String(1), ret.Error(2)
	}
	rc, ok := ret0.(io.ReadCloser)
	if !ok {
		return nil, ret.String(1), ret.Error(2)
	}
	return rc, ret.String(1), ret.Error(2)
}

func TestClient_DownloadDB(t *testing.T) {
	type listReleasesOutput struct {
		releases []*github.RepositoryRelease
		response *github.Response
		err      error
	}
	type listReleases struct {
		input  string
		output listReleasesOutput
	}

	type downloadAssetOutput struct {
		rc           io.ReadCloser
		redirectPath string
		err          error
	}
	type downloadAsset struct {
		input  int64
		output downloadAssetOutput
	}

	testCases := []struct {
		name          string
		fileName      string
		filePaths     []string
		listReleases  []listReleases
		downloadAsset []downloadAsset
		expectedError error
	}{
		{
			name:     "happy path",
			fileName: "trivy.db.gz",
			listReleases: []listReleases{
				{
					input: mock.Anything,
					output: listReleasesOutput{
						releases: []*github.RepositoryRelease{
							{
								// this release should be skipped due to the wrong prefix of the tag
								ID:   github.Int64(2),
								Name: github.String("v2-2020010101"),
								PublishedAt: &github.Timestamp{
									Time: time.Date(2020, 1, 1, 1, 59, 59, 0, time.UTC),
								},
								Assets: []*github.ReleaseAsset{
									{
										ID:   github.Int64(200),
										Name: github.String("trivy.db.gz"),
									},
								},
							},
							{
								ID:   github.Int64(1),
								Name: github.String("v1-2020123123"),
								PublishedAt: &github.Timestamp{
									Time: time.Date(2020, 12, 31, 23, 59, 59, 0, time.UTC),
								},
								Assets: []*github.ReleaseAsset{
									{
										ID:   github.Int64(100),
										Name: github.String("trivy.db.gz"),
									},
								},
							},
						},
					},
				},
			},
			downloadAsset: []downloadAsset{
				{
					input: 100,
					output: downloadAssetOutput{
						rc: ioutil.NopCloser(strings.NewReader("foo")),
					},
				},
			},
		},
		{
			name:     "happy path with redirect URL",
			fileName: "trivy.db.gz",
			listReleases: []listReleases{
				{
					input: mock.Anything,
					output: listReleasesOutput{
						releases: []*github.RepositoryRelease{
							{
								ID:   github.Int64(1),
								Name: github.String("v1-2020123123"),
								PublishedAt: &github.Timestamp{
									Time: time.Date(2020, 12, 31, 23, 59, 59, 0, time.UTC),
								},
								Assets: []*github.ReleaseAsset{
									{
										ID:   github.Int64(100),
										Name: github.String("trivy.db.gz"),
									},
								},
							},
						},
					},
				},
			},
			downloadAsset: []downloadAsset{
				{
					input: 100,
					output: downloadAssetOutput{
						redirectPath: "/happy",
					},
				},
			},
		},
		{
			name:     "happy path with inorder releases",
			fileName: "trivy.db.gz",
			listReleases: []listReleases{
				{
					input: mock.Anything,
					output: listReleasesOutput{
						releases: []*github.RepositoryRelease{
							{
								ID:   github.Int64(1),
								Name: github.String("v1-2019100123"),
								PublishedAt: &github.Timestamp{
									Time: time.Date(2019, 10, 1, 23, 59, 59, 0, time.UTC),
								},
								Assets: []*github.ReleaseAsset{
									{
										ID:   github.Int64(100),
										Name: github.String("trivy.db.gz"),
									},
								},
							},
							{
								// this release should be used because this is the latest
								ID:   github.Int64(3),
								Name: github.String("v1-2019100200"),
								PublishedAt: &github.Timestamp{
									Time: time.Date(2019, 10, 2, 0, 59, 59, 0, time.UTC),
								},
								Assets: []*github.ReleaseAsset{
									{
										ID:   github.Int64(300),
										Name: github.String("trivy.db.gz"),
									},
								},
							},
							{
								ID:   github.Int64(2),
								Name: github.String("v1-2019100122"),
								PublishedAt: &github.Timestamp{
									Time: time.Date(2019, 10, 1, 22, 59, 59, 0, time.UTC),
								},
								Assets: []*github.ReleaseAsset{
									{
										ID:   github.Int64(200),
										Name: github.String("trivy.db.gz"),
									},
								},
							},
						},
					},
				},
			},
			downloadAsset: []downloadAsset{
				{
					input: 300,
					output: downloadAssetOutput{
						rc: ioutil.NopCloser(strings.NewReader("foo")),
					},
				},
			},
		},
		{
			name:     "happy path with no asset",
			fileName: "trivy.db.gz",
			listReleases: []listReleases{
				{
					input: mock.Anything,
					output: listReleasesOutput{
						releases: []*github.RepositoryRelease{
							{
								// this release should be skipped due to no asset
								ID:   github.Int64(1),
								Name: github.String("v1-2019100123"),
								PublishedAt: &github.Timestamp{
									Time: time.Date(2019, 10, 1, 23, 59, 59, 0, time.UTC),
								},
							},
							{
								// this release should be skipped due to no asset
								ID:   github.Int64(3),
								Name: github.String("v1-2019100200"),
								PublishedAt: &github.Timestamp{
									Time: time.Date(2019, 10, 2, 0, 59, 59, 0, time.UTC),
								},
							},
							{
								// this release should be used because this release has assets
								ID:   github.Int64(2),
								Name: github.String("v1-2019100122"),
								PublishedAt: &github.Timestamp{
									Time: time.Date(2019, 10, 1, 22, 59, 59, 0, time.UTC),
								},
								Assets: []*github.ReleaseAsset{
									{
										ID:   github.Int64(200),
										Name: github.String("trivy.db.gz"),
									},
								},
							},
						},
					},
				},
			},
			downloadAsset: []downloadAsset{
				{
					input: 200,
					output: downloadAssetOutput{
						rc: ioutil.NopCloser(strings.NewReader("foo")),
					},
				},
			},
		},
		{
			name:     "no asset",
			fileName: "trivy.db.gz",
			listReleases: []listReleases{
				{
					input: mock.Anything,
					output: listReleasesOutput{
						releases: []*github.RepositoryRelease{
							{
								ID:   github.Int64(1),
								Name: github.String("v1-2020123000"),
								PublishedAt: &github.Timestamp{
									Time: time.Date(2020, 12, 31, 23, 59, 59, 0, time.UTC),
								},
							},
						},
					},
				},
			},
			expectedError: xerrors.New("DB file not found"),
		},
		{
			name:     "the file name doesn't match",
			fileName: "trivy-light.db.gz",
			listReleases: []listReleases{
				{
					input: mock.Anything,
					output: listReleasesOutput{
						releases: []*github.RepositoryRelease{
							{
								ID:   github.Int64(1),
								Name: github.String("v1-2020123000"),
								PublishedAt: &github.Timestamp{
									Time: time.Date(2020, 12, 31, 23, 59, 59, 0, time.UTC),
								},
								Assets: []*github.ReleaseAsset{
									{
										ID:   github.Int64(100),
										Name: github.String("trivy.db.gz"),
									},
								},
							},
						},
					},
				},
			},
			expectedError: xerrors.New("DB file not found"),
		},
		{
			name:     "ListReleases returns error",
			fileName: "trivy.db.gz",
			listReleases: []listReleases{
				{
					input: mock.Anything,
					output: listReleasesOutput{
						err: xerrors.New("something wrong"),
					},
				},
			},
			expectedError: xerrors.New("failed to list releases: something wrong"),
		},
		{
			name:     "DownloadAsset returns error",
			fileName: "trivy.db.gz",
			listReleases: []listReleases{
				{
					input: mock.Anything,
					output: listReleasesOutput{
						releases: []*github.RepositoryRelease{
							{
								ID:   github.Int64(1),
								Name: github.String("v1-2020123000"),
								PublishedAt: &github.Timestamp{
									Time: time.Date(2020, 12, 31, 23, 59, 59, 0, time.UTC),
								},
								Assets: []*github.ReleaseAsset{
									{
										ID:   github.Int64(100),
										Name: github.String("trivy.db.gz"),
									},
								},
							},
						},
					},
				},
			},
			downloadAsset: []downloadAsset{
				{
					input: 100,
					output: downloadAssetOutput{
						err: xerrors.New("something wrong"),
					},
				},
			},
			expectedError: xerrors.New("DB file not found"),
		},
		{
			name:     "404 error",
			fileName: "trivy.db.gz",
			listReleases: []listReleases{
				{
					input: mock.Anything,
					output: listReleasesOutput{
						releases: []*github.RepositoryRelease{
							{
								ID:   github.Int64(1),
								Name: github.String("v1-2020123000"),
								PublishedAt: &github.Timestamp{
									Time: time.Date(2020, 12, 31, 23, 59, 59, 0, time.UTC),
								},
								Assets: []*github.ReleaseAsset{
									{
										ID:   github.Int64(100),
										Name: github.String("trivy.db.gz"),
									},
								},
							},
						},
					},
				},
			},
			downloadAsset: []downloadAsset{
				{
					input: 100,
					output: downloadAssetOutput{
						redirectPath: "/not_found",
					},
				},
			},
			expectedError: xerrors.New("DB file not found"),
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/happy":
			_, _ = fmt.Fprintf(w, "happy")
		case "/not_found":
			http.NotFound(w, r)
		}
		return
	},
	))
	defer ts.Close()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockRepo := new(MockRepository)
			for _, lr := range tc.listReleases {
				mockRepo.On("ListReleases", mock.Anything, lr.input).Return(
					lr.output.releases, lr.output.response, lr.output.err,
				)
			}
			for _, da := range tc.downloadAsset {
				var redirectURL string
				if da.output.redirectPath != "" {
					u, _ := url.Parse(ts.URL)
					u.Path = path.Join(u.Path, da.output.redirectPath)
					redirectURL = u.String()
				}
				mockRepo.On("DownloadAsset", mock.Anything, da.input).Return(
					da.output.rc, redirectURL, da.output.err,
				)
			}

			client := Client{
				Repository: mockRepo,
			}

			ctx := context.Background()
			rc, _, err := client.DownloadDB(ctx, tc.fileName)

			switch {
			case tc.expectedError != nil:
				assert.EqualError(t, err, tc.expectedError.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
				assert.NotNil(t, rc, tc.name)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}
