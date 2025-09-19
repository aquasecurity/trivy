package pom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_pom_repositories(t *testing.T) {
	tests := []struct {
		name           string
		pom            *pom
		servers        []Server
		activeProfiles []string
		wantRelease    []string
		wantSnapshot   []string
	}{
		{
			name: "repo with releases enabled only",
			pom: &pom{content: &pomXML{Repositories: repositories{Repository: []repository{{
				ID:       "my-repo",
				URL:      "http://myrepo",
				Releases: repositoryPolicy{Enabled: true},
			}}}}},
			servers:        nil,
			activeProfiles: nil,
			wantRelease:    []string{"http://myrepo"},
			wantSnapshot:   nil,
		},
		{
			name: "repo with snapshots enabled only",
			pom: &pom{content: &pomXML{Repositories: repositories{Repository: []repository{{
				ID:        "snap-repo",
				URL:       "http://snap",
				Snapshots: repositoryPolicy{Enabled: true},
			}}}}},
			servers:        nil,
			activeProfiles: nil,
			wantRelease:    nil,
			wantSnapshot:   []string{"http://snap"},
		},
		{
			name: "disabled repo is ignored",
			pom: &pom{content: &pomXML{Repositories: repositories{Repository: []repository{{
				ID:        "disabled",
				URL:       "http://disabled",
				Releases:  repositoryPolicy{Enabled: false},
				Snapshots: repositoryPolicy{Enabled: false},
			}}}}},
			servers:        nil,
			activeProfiles: nil,
			wantRelease:    nil,
			wantSnapshot:   nil,
		},
		{
			name: "repo from active profile",
			pom: &pom{content: &pomXML{Profiles: []Profile{{
				ID: "p1",
				Repositories: []repository{{
					ID:       "p1-repo",
					URL:      "http://from-profile",
					Releases: repositoryPolicy{Enabled: true},
				}},
			}}}},
			servers:        nil,
			activeProfiles: []string{"p1"},
			wantRelease:    []string{"http://from-profile"},
			wantSnapshot:   nil,
		},
		{
			name: "repo with credentials from servers",
			pom: &pom{content: &pomXML{Repositories: repositories{Repository: []repository{{
				ID:       "secured-repo",
				URL:      "https://repo.example.com/maven",
				Releases: repositoryPolicy{Enabled: true},
			}}}}},
			servers: []Server{{
				ID:       "secured-repo",
				Username: "alice",
				Password: "s3cr3t",
			}},
			activeProfiles: nil,
			wantRelease:    []string{"https://alice:s3cr3t@repo.example.com/maven"},
			wantSnapshot:   nil,
		},
		{
			name: "duplicate repo id in pom and active profile (no dedupe; order preserved)",
			pom: &pom{content: &pomXML{
				Repositories: repositories{Repository: []repository{
					{
						ID:       "dup-release",
						URL:      "https://repo.dup.local/release",
						Releases: repositoryPolicy{Enabled: true},
					},
				}},
				Profiles: []Profile{
					{
						ID: "dup",
						Repositories: []repository{
							{
								ID:       "dup-release", // same id as in POM
								URL:      "https://repo.dup.local/alt",
								Releases: repositoryPolicy{Enabled: true},
							},
						},
					},
				},
			}},
			servers:        nil,
			activeProfiles: []string{"dup"},
			wantRelease: []string{
				"https://repo.dup.local/release",
				"https://repo.dup.local/alt",
			},
			wantSnapshot: nil,
		},
		{
			name: "multiple top-level & profile repos with mixed auth and policies",
			pom: &pom{content: &pomXML{
				Repositories: repositories{Repository: []repository{
					{
						ID:       "central",
						URL:      "https://repo.maven.apache.org/maven2",
						Releases: repositoryPolicy{Enabled: true},
					},
					{
						ID:       "corp-release",
						URL:      "https://repo.corp.local/releases",
						Releases: repositoryPolicy{Enabled: true},
					},
					{
						ID:        "corp-snapshots",
						URL:       "https://repo.corp.local/snapshots",
						Snapshots: repositoryPolicy{Enabled: true},
					},
				}},
				Profiles: []Profile{
					{
						ID: "dev",
						Repositories: []repository{
							{
								ID:       "dev-extra",
								URL:      "https://repo.dev.local/maven",
								Releases: repositoryPolicy{Enabled: true},
							},
						},
					},
					{
						ID: "qa", // not active -> ignored
						Repositories: []repository{
							{
								ID:       "qa-only",
								URL:      "https://repo.qa.local/maven",
								Releases: repositoryPolicy{Enabled: true},
							},
						},
					},
					{
						ID: "features",
						Repositories: []repository{
							{
								ID:        "feat-snap",
								URL:       "https://repo.features.local/snap",
								Snapshots: repositoryPolicy{Enabled: true},
							},
							{
								ID:       "noauth-release",
								URL:      "https://repo.features.local/release",
								Releases: repositoryPolicy{Enabled: true},
							},
						},
					},
				},
			}},
			servers: []Server{
				{ID: "corp-release", Username: "svc", Password: "token"},
				{ID: "corp-snapshots", Username: "svc", Password: "token2"},
				{ID: "dev-extra", Username: "svcdev", Password: "devpwd"},
				{ID: "feat-snap", Username: "feat", Password: "snap"},
				// intentionally no server for "noauth-release"
			},
			activeProfiles: []string{"dev", "features"},
			wantRelease: []string{
				"https://repo.maven.apache.org/maven2",
				"https://svc:token@repo.corp.local/releases",
				"https://svcdev:devpwd@repo.dev.local/maven",
				"https://repo.features.local/release",
			},
			wantSnapshot: []string{
				"https://svc:token2@repo.corp.local/snapshots",
				"https://feat:snap@repo.features.local/snap",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rel, snap := tt.pom.repositories(tt.servers, tt.activeProfiles)
			require.Equal(t, tt.wantRelease, rel)
			require.Equal(t, tt.wantSnapshot, snap)
		})
	}
}
