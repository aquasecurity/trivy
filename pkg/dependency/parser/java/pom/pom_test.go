package pom

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_Repositories(t *testing.T) {
	tests := []struct {
		name     string
		pomRepos pomRepositories
		repoOpts reposOptions
		want     []string
	}{
		{
			name: "enabled only release repository",
			pomRepos: pomRepositories{
				Repository: []pomRepository{
					{
						Releases: pomRepoEnabled{
							Enabled: "true",
						},
						URL: "https://test-release-repo.com",
					},
					{
						Snapshots: pomRepoEnabled{
							Enabled: "true",
						},
						URL: "https://test-snapshot-repo.com",
					},
				},
			},
			repoOpts: reposOptions{
				releaseReposEnable:  true,
				snapshotReposEnable: false,
			},
			want: []string{
				"https://test-release-repo.com",
			},
		},
		{
			name: "enabled only snapshot repository",
			pomRepos: pomRepositories{
				Repository: []pomRepository{
					{
						Releases: pomRepoEnabled{
							Enabled: "true",
						},
						URL: "https://test-release-repo.com",
					},
					{
						Snapshots: pomRepoEnabled{
							Enabled: "true",
						},
						URL: "https://test-snapshot-repo.com",
					},
				},
			},
			repoOpts: reposOptions{
				releaseReposEnable:  false,
				snapshotReposEnable: true,
			},
			want: []string{
				"https://test-snapshot-repo.com",
			},
		},
		{
			name: "repositories disabled",
			pomRepos: pomRepositories{
				Repository: []pomRepository{
					{
						Releases: pomRepoEnabled{
							Enabled: "true",
						},
						URL: "https://test-release-repo.com",
					},
					{
						Snapshots: pomRepoEnabled{
							Enabled: "true",
						},
						URL: "https://test-snapshot-repo.com",
					},
				},
			},
			repoOpts: reposOptions{
				releaseReposEnable:  false,
				snapshotReposEnable: false,
			},
			want: nil,
		},
		{
			name:     "pom doesn't contain repositories",
			pomRepos: pomRepositories{},
			repoOpts: reposOptions{
				releaseReposEnable:  true,
				snapshotReposEnable: true,
			},
			want: nil,
		},
		{
			name: "repository with credentials",
			pomRepos: pomRepositories{
				Repository: []pomRepository{
					{
						ID: "test-repo",
						Releases: pomRepoEnabled{
							Enabled: "true",
						},
						URL: "https://test-release-repo.com",
					},
				},
			},
			repoOpts: reposOptions{
				releaseReposEnable: true,
				servers: []Server{
					{
						ID:       "test-repo",
						Username: "test-user",
						Password: "test-password",
					},
				},
			},
			want: []string{
				"https://test-user:test-password@test-release-repo.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := pom{
				content: &pomXML{
					Repositories: tt.pomRepos,
				},
			}

			got := p.repositories(tt.repoOpts)
			require.Equal(t, tt.want, got)
		})
	}
}
