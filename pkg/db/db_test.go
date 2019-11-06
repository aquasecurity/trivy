package db

import (
	"context"
	"io"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"golang.org/x/xerrors"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockConfig struct {
	mock.Mock
}

func (_m *MockConfig) GetMetadata() (db.Metadata, error) {
	ret := _m.Called()
	ret0 := ret.Get(0)
	if ret0 == nil {
		return db.Metadata{}, ret.Error(1)
	}
	metadata, ok := ret0.(db.Metadata)
	if !ok {
		return db.Metadata{}, ret.Error(1)
	}
	return metadata, ret.Error(1)
}

type MockGitHubClient struct {
	mock.Mock
}

func (_m *MockGitHubClient) DownloadDB(ctx context.Context, fileName string) (io.ReadCloser, error) {
	ret := _m.Called(ctx, fileName)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return nil, ret.Error(1)
	}
	rc, ok := ret0.(io.ReadCloser)
	if !ok {
		return nil, ret.Error(1)
	}
	return rc, ret.Error(1)
}

func TestClient_Download(t *testing.T) {
	type getMetadataOutput struct {
		metadata db.Metadata
		err      error
	}

	type downloadDBOutput struct {
		fileName string
		err      error
	}
	type downloadDB struct {
		input  string
		output downloadDBOutput
	}

	testCases := []struct {
		name            string
		light           bool
		clock           clock.Clock
		getMetadata     []getMetadataOutput
		downloadDB      []downloadDB
		expectedContent []byte
		expectedError   error
	}{
		{
			name:  "happy path",
			light: false,
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			getMetadata: []getMetadataOutput{
				{
					metadata: db.Metadata{
						Version:    1,
						Type:       db.TypeFull,
						NextUpdate: time.Date(2019, 9, 1, 0, 0, 0, 0, time.UTC),
					},
				},
			},
			downloadDB: []downloadDB{
				{
					input: fullDB,
					output: downloadDBOutput{
						fileName: "testdata/test.db.gz",
					},
				},
			},
		},
		{
			name:  "happy path with different type",
			light: true,
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			getMetadata: []getMetadataOutput{
				{
					metadata: db.Metadata{
						Version:    1,
						Type:       db.TypeFull,
						NextUpdate: time.Date(2019, 9, 1, 0, 0, 0, 0, time.UTC),
					},
				},
			},
			downloadDB: []downloadDB{
				{
					input: lightDB,
					output: downloadDBOutput{
						fileName: "testdata/test.db.gz",
					},
				},
			},
		},
		{
			name:  "happy path with old schema version",
			light: true,
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			getMetadata: []getMetadataOutput{
				{
					metadata: db.Metadata{
						Version:    0,
						Type:       db.TypeFull,
						NextUpdate: time.Date(2020, 9, 1, 0, 0, 0, 0, time.UTC),
					},
				},
			},
			downloadDB: []downloadDB{
				{
					input: lightDB,
					output: downloadDBOutput{
						fileName: "testdata/test.db.gz",
					},
				},
			},
		},
		{
			name:  "skip downloading DB",
			light: false,
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			getMetadata: []getMetadataOutput{
				{
					metadata: db.Metadata{
						Version:    1,
						Type:       db.TypeFull,
						NextUpdate: time.Date(2019, 10, 2, 0, 0, 0, 0, time.UTC),
					},
				},
			},
		},
		{
			name:  "newer schema version",
			light: false,
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			getMetadata: []getMetadataOutput{
				{
					metadata: db.Metadata{
						Version:    2,
						Type:       db.TypeFull,
						NextUpdate: time.Date(2019, 10, 2, 0, 0, 0, 0, time.UTC),
					},
				},
			},
			expectedError: xerrors.New("The version of DB schema doesn't match"),
		},
		{
			name:  "DownloadDB returns an error",
			light: false,
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			getMetadata: []getMetadataOutput{
				{
					metadata: db.Metadata{
						Version:    1,
						Type:       db.TypeFull,
						NextUpdate: time.Date(2019, 9, 1, 0, 0, 0, 0, time.UTC),
					},
				},
			},
			downloadDB: []downloadDB{
				{
					input: fullDB,
					output: downloadDBOutput{
						err: xerrors.New("download failed"),
					},
				},
			},
			expectedError: xerrors.New("failed to download the DB file: failed to download vulnerability DB: download failed"),
		},
		{
			name:  "invalid gzip",
			light: false,
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			getMetadata: []getMetadataOutput{
				{
					metadata: db.Metadata{
						Version:    1,
						Type:       db.TypeFull,
						NextUpdate: time.Date(2019, 9, 1, 0, 0, 0, 0, time.UTC),
					},
				},
			},
			downloadDB: []downloadDB{
				{
					input: fullDB,
					output: downloadDBOutput{
						fileName: "testdata/invalid.db.gz",
					},
				},
			},
			expectedError: xerrors.New("unable to open new DB: failed to open db: invalid database"),
		},
	}

	if err := log.InitLogger(false, true); err != nil {
		require.NoError(t, err, "failed to init logger")
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockConfig := new(MockConfig)
			for _, gm := range tc.getMetadata {
				mockConfig.On("GetMetadata").Return(gm.metadata, gm.err)
			}

			mockGitHubConfig := new(MockGitHubClient)
			for _, dd := range tc.downloadDB {
				var rc io.ReadCloser
				if dd.output.fileName != "" {
					f, err := os.Open(dd.output.fileName)
					assert.NoError(t, err, tc.name)
					rc = f
				}

				mockGitHubConfig.On("DownloadDB", mock.Anything, dd.input).Return(
					rc, dd.output.err,
				)
			}

			dir, err := ioutil.TempDir("", "db")
			require.NoError(t, err, tc.name)
			defer os.RemoveAll(dir)

			err = db.Init(dir)
			require.NoError(t, err, tc.name)

			client := Client{
				dbc:          mockConfig,
				clock:        tc.clock,
				githubClient: mockGitHubConfig,
			}

			ctx := context.Background()
			err = client.Download(ctx, "test", dir, tc.light)

			switch {
			case tc.expectedError != nil:
				assert.EqualError(t, err, tc.expectedError.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}

			mockConfig.AssertExpectations(t)
			mockGitHubConfig.AssertExpectations(t)
		})
	}
}
