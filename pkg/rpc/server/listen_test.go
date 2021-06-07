package server

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-db/pkg/db"
	dbFile "github.com/aquasecurity/trivy/pkg/db"
	rpcCache "github.com/aquasecurity/trivy/rpc/cache"
)

func Test_dbWorker_update(t *testing.T) {
	timeNextUpdate := time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)
	timeUpdateAt := time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)

	type needsUpdateInput struct {
		appVersion string
		skip       bool
	}
	type needsUpdateOutput struct {
		needsUpdate bool
		err         error
	}
	type needsUpdate struct {
		input  needsUpdateInput
		output needsUpdateOutput
	}

	type download struct {
		call bool
		err  error
	}

	type args struct {
		appVersion string
	}
	tests := []struct {
		name        string
		needsUpdate needsUpdate
		download    download
		args        args
		want        db.Metadata
		wantErr     string
	}{
		{
			name: "happy path",
			needsUpdate: needsUpdate{
				input:  needsUpdateInput{appVersion: "1", skip: false},
				output: needsUpdateOutput{needsUpdate: true},
			},
			download: download{
				call: true,
			},
			args: args{appVersion: "1"},
			want: db.Metadata{
				Version:    1,
				Type:       db.TypeFull,
				NextUpdate: timeNextUpdate,
				UpdatedAt:  timeUpdateAt,
			},
		},
		{
			name: "not update",
			needsUpdate: needsUpdate{
				input:  needsUpdateInput{appVersion: "1", skip: false},
				output: needsUpdateOutput{needsUpdate: false},
			},
			args: args{appVersion: "1"},
		},
		{
			name: "NeedsUpdate returns an error",
			needsUpdate: needsUpdate{
				input:  needsUpdateInput{appVersion: "1", skip: false},
				output: needsUpdateOutput{err: xerrors.New("fail")},
			},
			args:    args{appVersion: "1"},
			wantErr: "failed to check if db needs an update",
		},
		{
			name: "Download returns an error",
			needsUpdate: needsUpdate{
				input:  needsUpdateInput{appVersion: "1", skip: false},
				output: needsUpdateOutput{needsUpdate: true},
			},
			download: download{
				call: true,
				err:  xerrors.New("fail"),
			},
			args:    args{appVersion: "1"},
			wantErr: "failed DB hot update",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheDir, err := ioutil.TempDir("", "server-test")
			require.NoError(t, err, tt.name)

			require.NoError(t, db.Init(cacheDir), tt.name)

			mockDBClient := new(dbFile.MockOperation)
			mockDBClient.On("NeedsUpdate",
				tt.needsUpdate.input.appVersion, false, tt.needsUpdate.input.skip).Return(
				tt.needsUpdate.output.needsUpdate, tt.needsUpdate.output.err)
			mockDBClient.On("UpdateMetadata", mock.Anything).Return(nil)

			if tt.download.call {
				mockDBClient.On("Download", mock.Anything, mock.Anything, false).Run(
					func(args mock.Arguments) {
						// fake download: copy testdata/new.db to tmpDir/db/trivy.db
						content, err := ioutil.ReadFile("testdata/new.db")
						require.NoError(t, err, tt.name)

						tmpDir := args.String(1)
						dbPath := db.Path(tmpDir)
						require.NoError(t, os.MkdirAll(filepath.Dir(dbPath), 0777), tt.name)
						err = ioutil.WriteFile(dbPath, content, 0444)
						require.NoError(t, err, tt.name)
					}).Return(tt.download.err)
			}

			w := newDBWorker(mockDBClient)

			var dbUpdateWg, requestWg sync.WaitGroup
			err = w.update(context.Background(), tt.args.appVersion, cacheDir,
				&dbUpdateWg, &requestWg)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				assert.NoError(t, err, tt.name)
			}

			if !tt.download.call {
				return
			}

			dbc := db.Config{}
			got, err := dbc.GetMetadata()
			assert.NoError(t, err, tt.name)
			assert.Equal(t, tt.want, got, tt.name)

			mockDBClient.AssertExpectations(t)
		})
	}
}

func Test_newServeMux(t *testing.T) {
	type args struct {
		token       string
		tokenHeader string
	}
	tests := []struct {
		name   string
		args   args
		path   string
		header http.Header
		want   int
	}{
		{
			name: "health check",
			path: "/healthz",
			want: http.StatusOK,
		},
		{
			name: "cache endpoint",
			path: path.Join(rpcCache.CachePathPrefix, "MissingBlobs"),
			header: http.Header{
				"Content-Type": []string{"application/protobuf"},
			},
			want: http.StatusOK,
		},
		{
			name: "with token",
			args: args{
				token:       "test",
				tokenHeader: "Authorization",
			},
			path: path.Join(rpcCache.CachePathPrefix, "MissingBlobs"),
			header: http.Header{
				"Authorization": []string{"test"},
				"Content-Type":  []string{"application/protobuf"},
			},
			want: http.StatusOK,
		},
		{
			name: "sad path: no handler",
			path: "/sad",
			header: http.Header{
				"Content-Type": []string{"application/protobuf"},
			},
			want: http.StatusNotFound,
		},
		{
			name: "sad path: invalid token",
			args: args{
				token:       "test",
				tokenHeader: "Authorization",
			},
			path: path.Join(rpcCache.CachePathPrefix, "MissingBlobs"),
			header: http.Header{
				"Content-Type": []string{"application/protobuf"},
			},
			want: http.StatusUnauthorized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbUpdateWg, requestWg := &sync.WaitGroup{}, &sync.WaitGroup{}

			c, err := cache.NewFSCache(t.TempDir())
			require.NoError(t, err)

			ts := httptest.NewServer(newServeMux(
				c, dbUpdateWg, requestWg, tt.args.token, tt.args.tokenHeader),
			)
			defer ts.Close()

			var resp *http.Response
			url := ts.URL + tt.path
			if tt.header == nil {
				resp, err = http.Get(url)
			} else {
				req, err := http.NewRequest(http.MethodPost, url, nil)
				require.NoError(t, err)

				req.Header = tt.header
				client := new(http.Client)
				resp, err = client.Do(req)
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, resp.StatusCode)
			defer resp.Body.Close()
		})
	}
}
