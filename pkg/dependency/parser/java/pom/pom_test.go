package pom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_effectiveRepositories(t *testing.T) {
	tests := []struct {
		name             string
		pom              *pom
		settings         *settings
		wantRepositories []repository
	}{
		{
			name: "pom with repository - no settings",
			pom: &pom{
				content: &pomXML{
					Repositories: repositories{
						Repository: []repository{
							{
								ID:       "my-repo",
								URL:      "http://myrepo",
								Releases: repositoryPolicy{Enabled: true},
							},
						},
					},
				},
			},
			settings: nil,
			wantRepositories: []repository{
				{
					ID:       "central",
					Name:     "Maven Central Repository",
					URL:      "https://repo.maven.apache.org/maven2/",
					Releases: repositoryPolicy{Enabled: true},
				},
				{
					ID:       "my-repo",
					URL:      "http://myrepo",
					Releases: repositoryPolicy{Enabled: true},
				},
			},
		},
		{
			name: "pom with central repository - no settings",
			pom: &pom{
				content: &pomXML{
					Repositories: repositories{
						Repository: []repository{
							{
								ID:       "central",
								URL:      "http://repo.maven.apache.org/maven2/will/be/overridden/by/internal/central",
								Releases: repositoryPolicy{Enabled: true},
							},
						},
					},
				},
			},
			settings: nil,
			wantRepositories: []repository{
				{
					ID:       "central",
					Name:     "Maven Central Repository",
					URL:      "https://repo.maven.apache.org/maven2/",
					Releases: repositoryPolicy{Enabled: true},
				},
			},
		},
		{
			name: "pom without repositories - no settings",
			pom: &pom{
				content: &pomXML{},
			},
			settings: nil,
			wantRepositories: []repository{
				{
					ID:       "central",
					Name:     "Maven Central Repository",
					URL:      "https://repo.maven.apache.org/maven2/",
					Releases: repositoryPolicy{Enabled: true},
				},
			},
		},
		{
			name: "pom with repository in profile - settings with different active profile",
			pom: &pom{
				content: &pomXML{
					Profiles: []Profile{
						{
							ID: "inactive",
							Repositories: []repository{
								{
									ID:       "inactive-repo",
									URL:      "http://inactive",
									Releases: repositoryPolicy{Enabled: true},
								},
							},
						},
					},
				},
			},
			settings: &settings{
				ActiveProfiles: []string{"not-this-one"},
			},
			wantRepositories: []repository{
				{
					ID:       "central",
					Name:     "Maven Central Repository",
					URL:      "https://repo.maven.apache.org/maven2/",
					Releases: repositoryPolicy{Enabled: true},
				},
			},
		},
		{
			name: "pom having repository with releases and snapshots disabled - no settings",
			pom: &pom{
				content: &pomXML{
					Repositories: repositories{
						Repository: []repository{
							{
								ID:        "disabled-repo",
								URL:       "http://disabled",
								Releases:  repositoryPolicy{Enabled: false},
								Snapshots: repositoryPolicy{Enabled: false},
							},
						},
					},
				},
			},
			settings: nil,
			wantRepositories: []repository{
				{
					ID:       "central",
					Name:     "Maven Central Repository",
					URL:      "https://repo.maven.apache.org/maven2/",
					Releases: repositoryPolicy{Enabled: true},
				},
				{
					ID:        "disabled-repo",
					URL:       "http://disabled",
					Releases:  repositoryPolicy{Enabled: false},
					Snapshots: repositoryPolicy{Enabled: false},
				},
			},
		},
		{
			name: "pom without repositories - settings with active profile containing repository",
			pom: &pom{
				content: &pomXML{},
			},
			settings: &settings{
				ActiveProfiles: []string{"default"},
				Profiles: []Profile{
					{
						ID: "default",
						Repositories: []repository{
							{
								ID:       "settings-repo",
								URL:      "http://from-settings",
								Releases: repositoryPolicy{Enabled: true},
							},
						},
					},
				},
			},
			wantRepositories: []repository{
				{
					ID:       "central",
					Name:     "Maven Central Repository",
					URL:      "https://repo.maven.apache.org/maven2/",
					Releases: repositoryPolicy{Enabled: true},
				},
				{
					ID:       "settings-repo",
					URL:      "http://from-settings",
					Releases: repositoryPolicy{Enabled: true},
				},
			},
		},
		{
			name: "pom without repositories - settings with profile that is active by default",
			pom: &pom{
				content: &pomXML{},
			},
			settings: &settings{
				Profiles: []Profile{
					{
						ID: "auto-default",
						Activation: activation{
							ActiveByDefault: true,
						},
						Repositories: []repository{
							{
								ID:       "auto-repo",
								URL:      "http://autodefault",
								Releases: repositoryPolicy{Enabled: true},
							},
						},
					},
				},
			},
			wantRepositories: []repository{
				{
					ID:       "central",
					Name:     "Maven Central Repository",
					URL:      "https://repo.maven.apache.org/maven2/",
					Releases: repositoryPolicy{Enabled: true},
				},
				{
					ID:       "auto-repo",
					URL:      "http://autodefault",
					Releases: repositoryPolicy{Enabled: true},
				},
			},
		},
		{
			name: "pom with repository - settings with profile that is active by default - both having same id",
			pom: &pom{
				content: &pomXML{
					Repositories: repositories{
						Repository: []repository{
							{
								ID:        "repo-with-same-id",
								URL:       "http://sameIdentifier",
								Releases:  repositoryPolicy{Enabled: true},
								Snapshots: repositoryPolicy{Enabled: false},
							},
						},
					},
				},
			},
			settings: &settings{
				Profiles: []Profile{
					{
						ID: "auto-default",
						Activation: activation{
							ActiveByDefault: true,
						},
						Repositories: []repository{
							{
								ID:        "repo-with-same-id",
								URL:       "http://sameIdentifierDifferentURL",
								Releases:  repositoryPolicy{Enabled: false},
								Snapshots: repositoryPolicy{Enabled: true},
							},
						},
					},
				},
			},
			wantRepositories: []repository{
				{
					ID:       "central",
					Name:     "Maven Central Repository",
					URL:      "https://repo.maven.apache.org/maven2/",
					Releases: repositoryPolicy{Enabled: true},
				},
				// Expecting the one from the pom to take precedence
				{
					ID:        "repo-with-same-id",
					URL:       "http://sameIdentifier",
					Releases:  repositoryPolicy{Enabled: true},
					Snapshots: repositoryPolicy{Enabled: false},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRepositories := tt.pom.effectiveRepositories(tt.settings)
			require.Equal(t, tt.wantRepositories, gotRepositories)
		})
	}
}
