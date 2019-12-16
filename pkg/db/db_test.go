package db

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/trivy/pkg/indicator"

	"github.com/stretchr/testify/require"

	"golang.org/x/xerrors"

	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/github"
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

func TestClient_NeedsUpdate(t *testing.T) {
	type getMetadataOutput struct {
		metadata db.Metadata
		err      error
	}

	testCases := []struct {
		name          string
		light         bool
		skip          bool
		clock         clock.Clock
		getMetadata   getMetadataOutput
		expected      bool
		expectedError error
	}{
		{
			name:  "happy path",
			light: false,
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			getMetadata: getMetadataOutput{
				metadata: db.Metadata{
					Version:    1,
					Type:       db.TypeFull,
					NextUpdate: time.Date(2019, 9, 1, 0, 0, 0, 0, time.UTC),
				},
			},
			expected: true,
		},
		{
			name:  "happy path for first run",
			light: false,
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			getMetadata: getMetadataOutput{
				metadata: db.Metadata{},
				err:      errors.New("get metadata failed"),
			},
			expected: true,
		},
		{
			name:  "happy path with different type",
			light: true,
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			getMetadata: getMetadataOutput{
				metadata: db.Metadata{
					Version:    1,
					Type:       db.TypeFull,
					NextUpdate: time.Date(2019, 9, 1, 0, 0, 0, 0, time.UTC),
				},
			},
			expected: true,
		},
		{
			name:  "happy path with old schema version",
			light: true,
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			getMetadata: getMetadataOutput{
				metadata: db.Metadata{
					Version:    0,
					Type:       db.TypeFull,
					NextUpdate: time.Date(2020, 9, 1, 0, 0, 0, 0, time.UTC),
				},
			},
			expected: true,
		},
		{
			name:  "happy path with --skip-update",
			light: false,
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			getMetadata: getMetadataOutput{
				metadata: db.Metadata{
					Version:    1,
					Type:       db.TypeFull,
					NextUpdate: time.Date(2019, 9, 1, 0, 0, 0, 0, time.UTC),
				},
			},
			skip:     true,
			expected: false,
		},
		{
			name:  "skip downloading DB",
			light: false,
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			getMetadata: getMetadataOutput{
				metadata: db.Metadata{
					Version:    1,
					Type:       db.TypeFull,
					NextUpdate: time.Date(2019, 10, 2, 0, 0, 0, 0, time.UTC),
				},
			},
			expected: false,
		},
		{
			name:  "newer schema version",
			light: false,
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			getMetadata: getMetadataOutput{
				metadata: db.Metadata{
					Version:    2,
					Type:       db.TypeFull,
					NextUpdate: time.Date(2019, 10, 2, 0, 0, 0, 0, time.UTC),
				},
			},
			expectedError: xerrors.New("the version of DB schema doesn't match. Local DB: 2, Expected: 1"),
		},
		{
			name:  "--skip-update on the first run",
			light: false,
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			getMetadata: getMetadataOutput{
				err: xerrors.New("this is the first run"),
			},
			skip:          true,
			expectedError: xerrors.New("--skip-update cannot be specified on the first run"),
		},
		{
			name:  "--skip-update with different schema version",
			light: false,
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			getMetadata: getMetadataOutput{
				metadata: db.Metadata{
					Version:    0,
					Type:       db.TypeFull,
					NextUpdate: time.Date(2019, 9, 1, 0, 0, 0, 0, time.UTC),
				},
			},
			skip:          true,
			expectedError: xerrors.New("--skip-update cannot be specified with the old DB"),
		},
	}

	if err := log.InitLogger(false, true); err != nil {
		require.NoError(t, err, "failed to init logger")
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockConfig := new(MockConfig)
			mockConfig.On("GetMetadata").Return(
				tc.getMetadata.metadata, tc.getMetadata.err)

			dir, err := ioutil.TempDir("", "db")
			require.NoError(t, err, tc.name)
			defer os.RemoveAll(dir)

			err = db.Init(dir)
			require.NoError(t, err, tc.name)

			client := Client{
				dbc:   mockConfig,
				clock: tc.clock,
			}

			needsUpdate, err := client.NeedsUpdate(context.Background(), "test", tc.light, tc.skip)

			switch {
			case tc.expectedError != nil:
				assert.EqualError(t, err, tc.expectedError.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}

			assert.Equal(t, tc.expected, needsUpdate)
			mockConfig.AssertExpectations(t)
		})
	}
}

func TestClient_Download(t *testing.T) {
	testCases := []struct {
		name            string
		light           bool
		downloadDB      []github.DownloadDBExpectation
		expectedContent []byte
		expectedError   error
	}{
		{
			name:  "happy path",
			light: false,
			downloadDB: []github.DownloadDBExpectation{
				{
					Args: github.DownloadDBInput{FileName: fullDB},
					ReturnArgs: github.DownloadDBOutput{
						FileName: "testdata/test.db.gz",
					},
				},
			},
		},
		{
			name:  "DownloadDB returns an error",
			light: false,
			downloadDB: []github.DownloadDBExpectation{
				{
					Args: github.DownloadDBInput{FileName: fullDB},
					ReturnArgs: github.DownloadDBOutput{
						Err: xerrors.New("download failed"),
					},
				},
			},
			expectedError: xerrors.New("failed to download vulnerability DB: download failed"),
		},
		{
			name:  "invalid gzip",
			light: false,
			downloadDB: []github.DownloadDBExpectation{
				{
					Args: github.DownloadDBInput{FileName: fullDB},
					ReturnArgs: github.DownloadDBOutput{
						FileName: "testdata/invalid.db.gz",
					},
				},
			},
			expectedError: xerrors.New("invalid gzip file: unexpected EOF"),
		},
	}

	err := log.InitLogger(false, true)
	require.NoError(t, err, "failed to init logger")

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockGitHubClient, err := github.NewMockClient(tc.downloadDB)
			require.NoError(t, err, tc.name)

			dir, err := ioutil.TempDir("", "db")
			require.NoError(t, err, tc.name)
			defer os.RemoveAll(dir)

			err = db.Init(dir)
			require.NoError(t, err, tc.name)

			pb := indicator.NewProgressBar(true)
			client := NewClient(db.Config{}, mockGitHubClient, pb, nil)
			ctx := context.Background()
			err = client.Download(ctx, dir, tc.light)

			switch {
			case tc.expectedError != nil:
				assert.EqualError(t, err, tc.expectedError.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}

			mockGitHubClient.AssertExpectations(t)
		})
	}
}
