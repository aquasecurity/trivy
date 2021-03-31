package types

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	git "github.com/go-git/go-git/v5"

	"github.com/aquasecurity/fanal/remote"
)

func TestGitConf_GetGitOption(t *testing.T) {
	type args struct {
		url string
		env map[string]string
	}
	tests := []struct {
		name       string
		args       args
		wantResult remote.Remote
		wantErr    string
	}{
		{
			name: "happy path default branch",
			args: args{
				url: "https://github.com/aquasecurity/trivy",
				env: map[string]string{},
			},
			wantResult: remote.Remote{
				IsBare: false,
				CloneOpts: &git.CloneOptions{
					URL:           "https://github.com/aquasecurity/trivy",
					RemoteName:    "origin",
					ReferenceName: "HEAD",
					SingleBranch:  true,
					Depth:         1,
					Tags:          git.AllTags,
				},
			},
		},
		{
			name: "happy path checkout branch",
			args: args{
				url: "https://github.com/aquasecurity/trivy",
				env: map[string]string{
					"TRIVY_GIT_BRANCH": "release",
				},
			},
			wantResult: remote.Remote{
				IsBare: false,
				CloneOpts: &git.CloneOptions{
					URL:           "https://github.com/aquasecurity/trivy",
					RemoteName:    "origin",
					ReferenceName: "refs/heads/release",
					SingleBranch:  true,
					Depth:         1,
					Tags:          git.AllTags,
				},
			},
		},
		{
			name: "happy path checkout tag",
			args: args{
				url: "https://github.com/aquasecurity/trivy",
				env: map[string]string{
					"TRIVY_GIT_TAG": "v1",
				},
			},
			wantResult: remote.Remote{
				IsBare: false,
				CloneOpts: &git.CloneOptions{
					URL:           "https://github.com/aquasecurity/trivy",
					RemoteName:    "origin",
					ReferenceName: "refs/tags/v1",
					SingleBranch:  true,
					Depth:         1,
					Tags:          git.AllTags,
				},
			},
		},
		{
			name: "happy path checkout commit",
			args: args{
				url: "https://github.com/aquasecurity/trivy",
				env: map[string]string{
					"TRIVY_GIT_COMMIT": "sha256:abcd",
				},
			},
			wantResult: remote.Remote{
				IsBare: false,
				Commit: "sha256:abcd",
				CloneOpts: &git.CloneOptions{
					URL:           "https://github.com/aquasecurity/trivy",
					RemoteName:    "origin",
					ReferenceName: "HEAD",
					SingleBranch:  false,
					Depth:         0,
					Tags:          git.AllTags,
				},
			},
		},
		{
			name: "happy path working directory",
			args: args{
				url: "https://github.com/aquasecurity/trivy",
				env: map[string]string{
					"TRIVY_GIT_CLONE_PARENT_DIRECTORY": "/mnt/writable",
				},
			},
			wantResult: remote.Remote{
				IsBare:          false,
				ParentDirectory: "/mnt/writable",
				CloneOpts: &git.CloneOptions{
					URL:           "https://github.com/aquasecurity/trivy",
					RemoteName:    "origin",
					ReferenceName: "HEAD",
					SingleBranch:  true,
					Depth:         1,
					Tags:          git.AllTags,
				},
			},
		},
		{
			name: "sad path invalid url",
			args: args{
				url: "ht tps://github.com/aquasecurity/trivy",
				env: map[string]string{},
			},
			wantErr: "unable to parse url",
		},
		{
			name: "sad path invalid key path",
			args: args{
				url: "git@github.com:aquasecurity/trivy",
				env: map[string]string{
					"TRIVY_GIT_KEY_PATH": "/no/key/here",
				},
			},
			wantErr: "unable to parse private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			os.Clearenv()
			for k, v := range tt.args.env {
				os.Setenv(k, v)
			}
			result, err := GetGitOption(tt.args.url)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				require.Contains(t, err.Error(), tt.wantErr, tt.name)
			} else {
				require.NoError(t, err, tt.name)

				assert.Equal(t, tt.wantResult.ParentDirectory, result.ParentDirectory, tt.name)
				assert.Equal(t, tt.wantResult.IsBare, result.IsBare, tt.name)
				assert.Equal(t, tt.wantResult.Commit, result.Commit, tt.name)

				result.CloneOpts.Progress = nil // pointer causes failed assertion
				assert.Equal(t, *tt.wantResult.CloneOpts, *result.CloneOpts, tt.name)
			}
		})
	}
}
