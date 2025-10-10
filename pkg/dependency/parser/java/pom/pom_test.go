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
				ID:        "my-repo",
				URL:       "http://myrepo",
				Releases:  repositoryPolicy{Enabled: boolPtr(true)},
				Snapshots: repositoryPolicy{Enabled: boolPtr(false)},
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
				Releases:  repositoryPolicy{Enabled: boolPtr(false)},
				Snapshots: repositoryPolicy{Enabled: boolPtr(true)},
			}}}}},
			servers:        nil,
			activeProfiles: nil,
			wantRelease:    nil,
			wantSnapshot:   []string{"http://snap"},
		},
		{
			name: "repo with releases & snapshots omitted is included (default to enabled)",
			pom: &pom{content: &pomXML{Repositories: repositories{Repository: []repository{{
				ID:  "default-both",
				URL: "http://both",
				// No Releases/Snapshots blocks provided -> both should default to enabled
			}}}}},
			servers:        nil,
			activeProfiles: nil,
			wantRelease:    []string{"http://both"},
			wantSnapshot:   []string{"http://both"},
		},
		{
			name: "repos with releases & snapshots explicitly disabled repo is ignored",
			pom: &pom{content: &pomXML{Repositories: repositories{Repository: []repository{{
				ID:        "disabled",
				URL:       "http://disabled",
				Releases:  repositoryPolicy{Enabled: boolPtr(false)},
				Snapshots: repositoryPolicy{Enabled: boolPtr(false)},
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
					ID:        "p1-repo",
					URL:       "http://from-profile",
					Releases:  repositoryPolicy{Enabled: boolPtr(true)},
					Snapshots: repositoryPolicy{Enabled: boolPtr(false)},
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
				ID:        "secured-repo",
				URL:       "https://repo.example.com/maven",
				Releases:  repositoryPolicy{Enabled: boolPtr(true)},
				Snapshots: repositoryPolicy{Enabled: boolPtr(false)},
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
						ID:        "dup-release",
						URL:       "https://repo.dup.local/release",
						Releases:  repositoryPolicy{Enabled: boolPtr(true)},
						Snapshots: repositoryPolicy{Enabled: boolPtr(false)},
					},
				}},
				Profiles: []Profile{
					{
						ID: "dup",
						Repositories: []repository{
							{
								ID:        "dup-release", // same id as in POM
								URL:       "https://repo.dup.local/alt",
								Releases:  repositoryPolicy{Enabled: boolPtr(true)},
								Snapshots: repositoryPolicy{Enabled: boolPtr(false)},
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
						ID:        "central",
						URL:       "https://repo.maven.apache.org/maven2",
						Releases:  repositoryPolicy{Enabled: boolPtr(true)},
						Snapshots: repositoryPolicy{Enabled: boolPtr(false)},
					},
					{
						ID:        "corp-release",
						URL:       "https://repo.corp.local/releases",
						Releases:  repositoryPolicy{Enabled: boolPtr(true)},
						Snapshots: repositoryPolicy{Enabled: boolPtr(false)},
					},
					{
						ID:        "corp-snapshots",
						URL:       "https://repo.corp.local/snapshots",
						Releases:  repositoryPolicy{Enabled: boolPtr(false)},
						Snapshots: repositoryPolicy{Enabled: boolPtr(true)},
					},
				}},
				Profiles: []Profile{
					{
						ID: "dev",
						Repositories: []repository{
							{
								ID:        "dev-extra",
								URL:       "https://repo.dev.local/maven",
								Releases:  repositoryPolicy{Enabled: boolPtr(true)},
								Snapshots: repositoryPolicy{Enabled: boolPtr(false)},
							},
						},
					},
					{
						ID: "qa", // not active -> ignored
						Repositories: []repository{
							{
								ID:        "qa-only",
								URL:       "https://repo.qa.local/maven",
								Releases:  repositoryPolicy{Enabled: boolPtr(true)},
								Snapshots: repositoryPolicy{Enabled: boolPtr(false)},
							},
						},
					},
					{
						ID: "features",
						Repositories: []repository{
							{
								ID:        "feat-snap",
								URL:       "https://repo.features.local/snap",
								Releases:  repositoryPolicy{Enabled: boolPtr(false)},
								Snapshots: repositoryPolicy{Enabled: boolPtr(true)},
							},
							{
								ID:        "noauth-release",
								URL:       "https://repo.features.local/release",
								Releases:  repositoryPolicy{Enabled: boolPtr(true)},
								Snapshots: repositoryPolicy{Enabled: boolPtr(false)},
							},
						},
					},
					{
						ID: "implicit",
						Repositories: []repository{
							{
								ID:  "implicitly-enabled-both-omitted",
								URL: "https://repo.features.local/implicit-both-omitted",
								// No Releases/Snapshots blocks provided -> both should default to enabled
							},
							{
								ID:        "implicitly-enabled-both-nil",
								URL:       "https://repo.features.local/implicit-both-nil",
								Releases:  repositoryPolicy{Enabled: nil},
								Snapshots: repositoryPolicy{Enabled: nil},
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
			activeProfiles: []string{"dev", "features", "implicit"},
			wantRelease: []string{
				"https://repo.maven.apache.org/maven2",
				"https://svc:token@repo.corp.local/releases",
				"https://svcdev:devpwd@repo.dev.local/maven",
				"https://repo.features.local/release",
				"https://repo.features.local/implicit-both-omitted",
				"https://repo.features.local/implicit-both-nil",
			},
			wantSnapshot: []string{
				"https://svc:token2@repo.corp.local/snapshots",
				"https://feat:snap@repo.features.local/snap",
				"https://repo.features.local/implicit-both-omitted",
				"https://repo.features.local/implicit-both-nil",
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
