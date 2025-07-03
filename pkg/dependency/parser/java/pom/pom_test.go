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
								ID:       "central",
								URL:      "http://repo.maven.apache.org/maven2",
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
					URL:      "http://repo.maven.apache.org/maven2",
					Releases: repositoryPolicy{Enabled: true},
				},
			},
		},
		{
			name: "pom with repository and profile containing repository - settings with active profile and mirror",
			pom: &pom{
				content: &pomXML{
					Repositories: repositories{
						Repository: []repository{
							{
								ID:        "r1-releases",
								URL:       "http://repo1",
								Releases:  repositoryPolicy{Enabled: true},
								Snapshots: repositoryPolicy{Enabled: true},
							},
						},
					},
					Profiles: []Profile{
						{
							ID: "p1",
							Repositories: []repository{
								{
									ID:        "r2-snapshots",
									URL:       "http://repo2",
									Releases:  repositoryPolicy{Enabled: false},
									Snapshots: repositoryPolicy{Enabled: true},
								},
							},
						},
					},
				},
			},
			settings: &settings{
				ActiveProfiles: []string{"p1"},
				Mirrors: []Mirror{
					{ID: "mirror-r1-releases", MirrorOf: "r1-releases", URL: "http://mirror1"},
				},
			},
			wantRepositories: []repository{
				{
					ID:       "r1-releases",
					URL:      "http://mirror1",
					Releases: repositoryPolicy{Enabled: true},
					// When a mirror is applied, it enables both releases and snapshots
					Snapshots: repositoryPolicy{Enabled: true},
				},
				{
					ID:        "r2-snapshots",
					URL:       "http://repo2",
					Releases:  repositoryPolicy{Enabled: false},
					Snapshots: repositoryPolicy{Enabled: true},
				},
			},
		},
		{
			name: "pom without repositories - no settings",
			pom: &pom{
				content: &pomXML{},
			},
			settings:         nil,
			wantRepositories: []repository{},
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
			wantRepositories: []repository{},
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
					ID:       "settings-repo",
					URL:      "http://from-settings",
					Releases: repositoryPolicy{Enabled: true},
				},
			},
		},
		{
			name: "pom with repository - settings with mirror for a different repository",
			pom: &pom{
				content: &pomXML{
					Repositories: repositories{
						Repository: []repository{
							{
								ID:       "real-repo",
								URL:      "http://real",
								Releases: repositoryPolicy{Enabled: true},
							},
						},
					},
				},
			},
			settings: &settings{
				Mirrors: []Mirror{
					{ID: "unused", MirrorOf: "nonexistent", URL: "http://mirror"},
				},
			},
			wantRepositories: []repository{
				{
					ID:       "real-repo",
					URL:      "http://real",
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
