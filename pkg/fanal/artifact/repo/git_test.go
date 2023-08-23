//go:build unix

package repo

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/sosedoff/gitkit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/config/all"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/secret"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
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
		target     string
		c          cache.ArtifactCache
		noProgress bool
		repoBranch string
		repoTag    string
		repoCommit string
	}
	tests := []struct {
		name      string
		args      args
		assertion assert.ErrorAssertionFunc
	}{
		{
			name: "remote repo",
			args: args{
				target:     ts.URL + "/test.git",
				c:          nil,
				noProgress: false,
			},
			assertion: assert.NoError,
		},
		{
			name: "local repo",
			args: args{
				target:     "testdata",
				c:          nil,
				noProgress: false,
			},
			assertion: assert.NoError,
		},
		{
			name: "happy noProgress",
			args: args{
				target:     ts.URL + "/test.git",
				c:          nil,
				noProgress: true,
			},
			assertion: assert.NoError,
		},
		{
			name: "branch",
			args: args{
				target:     ts.URL + "/test.git",
				c:          nil,
				repoBranch: "valid-branch",
			},
			assertion: assert.NoError,
		},
		{
			name: "tag",
			args: args{
				target:  ts.URL + "/test.git",
				c:       nil,
				repoTag: "v1.0.0",
			},
			assertion: assert.NoError,
		},
		{
			name: "commit",
			args: args{
				target:     ts.URL + "/test.git",
				c:          nil,
				repoCommit: "6ac152fe2b87cb5e243414df71790a32912e778d",
			},
			assertion: assert.NoError,
		},
		{
			name: "sad path",
			args: args{
				target:     ts.URL + "/unknown.git",
				c:          nil,
				noProgress: false,
			},
			assertion: func(t assert.TestingT, err error, args ...interface{}) bool {
				return assert.ErrorContains(t, err, "repository not found")
			},
		},
		{
			name: "invalid url",
			args: args{
				target:     "ht tp://foo.com",
				c:          nil,
				noProgress: false,
			},
			assertion: func(t assert.TestingT, err error, args ...interface{}) bool {
				return assert.ErrorContains(t, err, "url parse error")
			},
		},
		{
			name: "invalid branch",
			args: args{
				target:     ts.URL + "/test.git",
				c:          nil,
				repoBranch: "invalid-branch",
			},
			assertion: func(t assert.TestingT, err error, args ...interface{}) bool {
				return assert.ErrorContains(t, err, `couldn't find remote ref "refs/heads/invalid-branch"`)
			},
		},
		{
			name: "invalid tag",
			args: args{
				target:  ts.URL + "/test.git",
				c:       nil,
				repoTag: "v1.0.9",
			},
			assertion: func(t assert.TestingT, err error, args ...interface{}) bool {
				return assert.ErrorContains(t, err, `couldn't find remote ref "refs/tags/v1.0.9"`)
			},
		},
		{
			name: "invalid commit",
			args: args{
				target:     ts.URL + "/test.git",
				c:          nil,
				repoCommit: "6ac152fe2b87cb5e243414df71790a32912e778e",
			},
			assertion: func(t assert.TestingT, err error, args ...interface{}) bool {
				return assert.ErrorContains(t, err, "git checkout error: object not found")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, cleanup, err := NewArtifact(tt.args.target, tt.args.c, artifact.Option{
				NoProgress: tt.args.noProgress,
				RepoBranch: tt.args.repoBranch,
				RepoTag:    tt.args.repoTag,
				RepoCommit: tt.args.repoCommit,
			})
			tt.assertion(t, err)
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
				Type: types.ArtifactRepository,
				ID:   "sha256:1fa928c33b16a335015ce96e1384127f8463c4f27ed0786806a6d4584b63d091",
				BlobIDs: []string{
					"sha256:1fa928c33b16a335015ce96e1384127f8463c4f27ed0786806a6d4584b63d091",
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
