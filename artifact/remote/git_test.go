package remote

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/sosedoff/gitkit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
)

func setupGitServer() (*httptest.Server, error) {
	service := gitkit.New(gitkit.Config{
		Dir:        "./testdata",
		AutoCreate: false,
	})

	if err := service.Setup(); err != nil {
		return nil, err
	}

	ts := httptest.NewServer(service)

	return ts, nil
}

func TestNewArtifact(t *testing.T) {
	ts, err := setupGitServer()
	require.NoError(t, err)
	defer ts.Close()

	type args struct {
		rawurl     string
		c          cache.ArtifactCache
		noProgress bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "happy path",
			args: args{
				rawurl:     ts.URL + "/test.git",
				c:          nil,
				noProgress: false,
			},
		},
		{
			name: "happy noProgress",
			args: args{
				rawurl:     ts.URL + "/test.git",
				c:          nil,
				noProgress: true,
			},
		},
		{
			name: "sad path",
			args: args{
				rawurl:     ts.URL + "/unknown.git",
				c:          nil,
				noProgress: false,
			},
			wantErr: true,
		},
		{
			name: "invalid url",
			args: args{
				rawurl:     "ht tp://foo.com",
				c:          nil,
				noProgress: false,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, cleanup, err := NewArtifact(tt.args.rawurl, tt.args.c, artifact.Option{NoProgress: tt.args.noProgress})
			assert.Equal(t, tt.wantErr, err != nil)
			defer cleanup()
		})
	}
}

func TestArtifact_Inspect(t *testing.T) {
	ts, err := setupGitServer()
	require.NoError(t, err)
	defer ts.Close()

	tests := []struct {
		name    string
		rawurl  string
		want    types.ArtifactReference
		wantErr bool
	}{
		{
			name:   "happy path",
			rawurl: ts.URL + "/test.git",
			want: types.ArtifactReference{
				Name: ts.URL + "/test.git",
				Type: types.ArtifactRemoteRepository,
				ID:   "sha256:11c30bc7079b06757c02daf7c01a76d9f57f7a7ed421d3967b0f9d0e72da7229",
				BlobIDs: []string{
					"sha256:11c30bc7079b06757c02daf7c01a76d9f57f7a7ed421d3967b0f9d0e72da7229",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsCache, err := cache.NewFSCache(t.TempDir())
			require.NoError(t, err)

			art, cleanup, err := NewArtifact(tt.rawurl, fsCache, artifact.Option{})
			require.NoError(t, err)
			defer cleanup()

			ref, err := art.Inspect(context.Background())
			assert.NoError(t, err)
			assert.Equal(t, tt.want, ref)
		})
	}
}

func Test_newURL(t *testing.T) {
	type args struct {
		rawurl string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				rawurl: "https://github.com/aquasecurity/fanal",
			},
			want: "https://github.com/aquasecurity/fanal",
		},
		{
			name: "happy path: no scheme",
			args: args{
				rawurl: "github.com/aquasecurity/fanal",
			},
			want: "https://github.com/aquasecurity/fanal",
		},
		{
			name: "sad path: invalid url",
			args: args{
				rawurl: "ht tp://foo.com",
			},
			wantErr: "first path segment in URL cannot contain colon",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newURL(tt.args.rawurl)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.want, got.String())
		})
	}
}
