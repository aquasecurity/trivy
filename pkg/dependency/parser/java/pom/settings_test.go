package pom

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ReadSettings(t *testing.T) {
	tests := []struct {
		name         string
		envs         map[string]string
		wantSettings settings
	}{
		{
			name: "happy path with only global settings",
			envs: map[string]string{
				"HOME":       "",
				"MAVEN_HOME": filepath.Join("testdata", "settings", "global"),
			},
			wantSettings: settings{
				LocalRepository: "testdata/repository",
				Servers: []Server{
					{
						ID: "global-server",
					},
					{
						ID:       "server-with-credentials",
						Username: "test-user",
						Password: "test-password-from-global",
					},
					{
						ID:       "server-with-name-only",
						Username: "test-user-only",
					},
				},
			},
		},
		{
			name: "happy path with only user settings",
			envs: map[string]string{
				"HOME":       filepath.Join("testdata", "settings", "user"),
				"MAVEN_HOME": "NOT_EXISTING_PATH",
			},
			wantSettings: settings{
				LocalRepository: "testdata/user/repository",
				Servers: []Server{
					{
						ID: "user-server",
					},
					{
						ID:       "server-with-credentials",
						Username: "test-user",
						Password: "test-password",
					},
					{
						ID:       "server-with-name-only",
						Username: "test-user-only",
					},
				},
			},
		},
		{
			// $ mvn help:effective-settings
			//[INFO] ------------------< org.apache.maven:standalone-pom >-------------------
			//[INFO] --- maven-help-plugin:3.4.0:effective-settings (default-cli) @ standalone-pom ---
			//Effective user-specific configuration settings:
			//
			//<?xml version="1.0" encoding="UTF-8"?>
			//<settings xmlns="http://maven.apache.org/SETTINGS/1.1.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.1.0 http://maven.apache.org/xsd/settings-1.1.0.xsd">
			//  <localRepository>/root/testdata/user/repository</localRepository>
			//  <servers>
			//    <server>
			//      <id>user-server</id>
			//    </server>
			//    <server>
			//      <username>test-user</username>
			//      <password>***</password>
			//      <id>server-with-credentials</id>
			//    </server>
			//    <server>
			//      <username>test-user-only</username>
			//      <id>server-with-name-only</id>
			//    </server>
			//    <server>
			//      <id>global-server</id>
			//    </server>
			//  </servers>
			//</settings>
			name: "happy path with global and user settings",
			envs: map[string]string{
				"HOME":       filepath.Join("testdata", "settings", "user"),
				"MAVEN_HOME": filepath.Join("testdata", "settings", "global"),
			},
			wantSettings: settings{
				LocalRepository: "testdata/user/repository",
				Servers: []Server{
					{
						ID: "user-server",
					},
					{
						ID:       "server-with-credentials",
						Username: "test-user",
						Password: "test-password",
					},
					{
						ID:       "server-with-name-only",
						Username: "test-user-only",
					},
					{
						ID: "global-server",
					},
				},
			},
		},
		{
			name: "without settings",
			envs: map[string]string{
				"HOME":       "",
				"MAVEN_HOME": "NOT_EXISTING_PATH",
			},
			wantSettings: settings{},
		},
		{
			name: "environment placeholders are dereferenced",
			envs: map[string]string{
				"HOME":            filepath.Join("testdata", "settings", "user-settings-with-env-placeholders"),
				"MAVEN_HOME":      "NOT_EXISTING_PATH",
				"LOCAL_REPO_PT_1": "part1",
				"LOCAL_REPO_PT_2": "part2",
				"SERVER_ID":       "server-id-from-env",
				"USERNAME":        "username-from-env",
				"PASSWORD":        "password-from-env",
			},
			wantSettings: settings{
				LocalRepository: "part1/part2/.m2/repository",
				Servers: []Server{
					{
						ID: "user-server",
					},
					{
						ID:       "server-id-from-env",
						Username: "username-from-env",
						Password: "password-from-env",
					},
					{
						ID:       "server-with-name-only",
						Username: "test-user-only",
					},
				},
			},
		},
		{
			name: "happy path with user settings containing profile and repositories",
			envs: map[string]string{
				"HOME":           filepath.Join("testdata", "settings", "user-settings-with-profile-containing-repositories"),
				"MAVEN_HOME":     "NOT_EXISTING_PATH",
				"ACTIVE_PROFILE": "test-cicd",
			},
			wantSettings: settings{
				LocalRepository: "",
				Servers: []Server{
					{
						ID:       "mycompany-internal-releases",
						Username: "mypassword",
						Password: "mypassword",
					},
					{
						ID:       "mycompany-internal-snapshots",
						Username: "mypassword",
						Password: "mypassword",
					},
				},
				Profiles: []Profile{
					{
						ID: "mycompany",
						Repositories: []repository{
							{
								ID:  "mycompany-internal-releases",
								URL: "https://mycompany.example.com/repository/internal-releases",
								Releases: repositoryPolicy{
									Enabled: "true",
								},
								Snapshots: repositoryPolicy{
									Enabled: "false",
								},
							},
							{
								ID:  "mycompany-internal-snapshots",
								URL: "https://mycompany.example.com/repository/internal-snapshots",
								Releases: repositoryPolicy{
									Enabled: "false",
								},
								Snapshots: repositoryPolicy{
									Enabled: "true",
								},
							},
						},
					},
				},
				ActiveProfiles: []string{"mycompany", "test-cicd"},
				Mirrors: []Mirror{
					{
						ID:       "mycompany-maven-central-mirror",
						Name:     "mycompany-maven-central-mirror",
						URL:      "https://mycompany.example.com/repository/maven-central-mirror",
						MirrorOf: "central",
					},
				},
			},
		},
		{
			name: "happy path with user settings containing http headers for authentication",
			envs: map[string]string{
				"HOME":           filepath.Join("testdata", "settings", "user-settings-with-http-headers"),
				"MAVEN_HOME":     "NOT_EXISTING_PATH",
				"ACTIVE_PROFILE": "test-cicd",
			},
			wantSettings: settings{
				LocalRepository: "",
				Servers: []Server{
					{
						ID: "mycompany-internal-releases",
						Configuration: Configuration{
							HTTPHeaders: struct {
								Property []struct {
									Name  string `xml:"name"`
									Value string `xml:"value"`
								} `xml:"property"`
							}{
								Property: []struct {
									Name  string `xml:"name"`
									Value string `xml:"value"`
								}{
									{Name: "Private-Token", Value: "MyPrivateToken"},
								},
							},
						},
					},
					{
						ID: "mycompany-internal-snapshots",
						Configuration: Configuration{
							HTTPHeaders: struct {
								Property []struct {
									Name  string `xml:"name"`
									Value string `xml:"value"`
								} `xml:"property"`
							}{
								Property: []struct {
									Name  string `xml:"name"`
									Value string `xml:"value"`
								}{
									{Name: "Private-Token", Value: "MyPrivateToken"},
								},
							},
						},
					},
				},
				Profiles: []Profile{
					{
						ID: "mycompany",
						Repositories: []repository{
							{
								ID:  "mycompany-internal-releases",
								URL: "https://mycompany.example.com/repository/internal-releases",
								Releases: repositoryPolicy{
									Enabled: "true",
								},
								Snapshots: repositoryPolicy{
									Enabled: "false",
								},
							},
							{
								ID:  "mycompany-internal-snapshots",
								URL: "https://mycompany.example.com/repository/internal-snapshots",
								Releases: repositoryPolicy{
									Enabled: "false",
								},
								Snapshots: repositoryPolicy{
									Enabled: "true",
								},
							},
						},
					},
				},
				ActiveProfiles: []string{"mycompany", "test-cicd"},
				Mirrors: []Mirror{
					{
						ID:       "mycompany-maven-central-mirror",
						Name:     "mycompany-maven-central-mirror",
						URL:      "https://mycompany.example.com/repository/maven-central-mirror",
						MirrorOf: "central",
					},
				},
			},
		},
		{
			name: "happy path with global and user settings containing profile and repositories",
			envs: map[string]string{
				"HOME":           filepath.Join("testdata", "settings", "user-settings-with-profile-containing-repositories"),
				"MAVEN_HOME":     filepath.Join("testdata", "settings", "global-settings-with-profile-containing-repositories"),
				"ACTIVE_PROFILE": "test-cicd",
			},
			wantSettings: settings{
				LocalRepository: "",
				Servers: []Server{
					{
						ID:       "mycompany-internal-releases",
						Username: "mypassword",
						Password: "mypassword",
					},
					{
						ID:       "mycompany-internal-snapshots",
						Username: "mypassword",
						Password: "mypassword",
					},
					{
						ID:       "mycompany-global-releases",
						Username: "mypassword",
						Password: "mypassword",
					},
				},
				Profiles: []Profile{
					{
						ID: "mycompany",
						Repositories: []repository{
							{
								ID:  "mycompany-internal-releases",
								URL: "https://mycompany.example.com/repository/internal-releases",
								Releases: repositoryPolicy{
									Enabled: "true",
								},
								Snapshots: repositoryPolicy{
									Enabled: "false",
								},
							},
							{
								ID:  "mycompany-internal-snapshots",
								URL: "https://mycompany.example.com/repository/internal-snapshots",
								Releases: repositoryPolicy{
									Enabled: "false",
								},
								Snapshots: repositoryPolicy{
									Enabled: "true",
								},
							},
						},
					},
					{
						ID: "test-cicd",
						Repositories: []repository{
							{
								ID:  "mycompany-internal-releases",
								URL: "https://mycompany.example.com/repository/internal-releases",
								Releases: repositoryPolicy{
									Enabled: "true",
								},
								Snapshots: repositoryPolicy{
									Enabled: "false",
								},
							},
							{
								ID:  "mycompany-global-releases",
								URL: "https://mycompany.example.com/repository/global-releases",
								Releases: repositoryPolicy{
									Enabled: "true",
								},
								Snapshots: repositoryPolicy{
									Enabled: "false",
								},
							},
						},
					},
					{
						ID: "default",
						Repositories: []repository{
							{
								ID:  "mycompany-default-releases",
								URL: "https://mycompany.example.com/repository/default-releases",
								Releases: repositoryPolicy{
									Enabled: "true",
								},
								Snapshots: repositoryPolicy{
									Enabled: "false",
								},
							},
						},
						Activation: activation{ActiveByDefault: true},
					},
				},
				ActiveProfiles: []string{"mycompany", "test-cicd"},
				Mirrors: []Mirror{
					{
						ID:       "mycompany-maven-central-mirror",
						Name:     "mycompany-maven-central-mirror",
						URL:      "https://mycompany.example.com/repository/maven-central-mirror",
						MirrorOf: "central",
					},
					{
						ID:       "google-maven-central",
						Name:     "GCS Maven Central mirror EU",
						URL:      "https://maven-central-eu.storage-download.googleapis.com/maven2/",
						MirrorOf: "*,!mycompany-internal-releases,!mycompany-global-releases",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for env, settingsDir := range tt.envs {
				t.Setenv(env, settingsDir)
			}

			gotSettings := readSettings()
			require.Equal(t, tt.wantSettings, gotSettings)
		})
	}
}

func Test_getActiveProfiles(t *testing.T) {
	s := settings{
		Profiles: []Profile{
			{
				ID: "p1",
				Repositories: []repository{
					{ID: "r1"},
					{ID: "r2"},
				},
			},
			{
				ID: "p2",
				Repositories: []repository{
					{ID: "r3"},
				},
				Activation: activation{ActiveByDefault: true},
			},
			{
				ID: "p3",
				Repositories: []repository{
					{ID: "r4"}},
			},
			{
				ID: "p1",
				Repositories: []repository{
					{ID: "r1"},
					{ID: "r2"},
					{ID: "r3"},
				},
			},
		},
		ActiveProfiles: []string{"p1"},
	}
	got := s.getActiveProfiles()
	require.Len(t, got, 2)
	require.Equal(t, "p1", got[0].ID)
	require.Equal(t, "p2", got[1].ID)
}

func Test_findMirrorForRepository(t *testing.T) {
	s := settings{
		Mirrors: []Mirror{
			{ID: "mirror-generic", MirrorOf: "*, !test"},
			{ID: "mirror-central", MirrorOf: "central"},
		},
	}
	require.Equal(t, "mirror-central", s.findMirrorForRepository("central").ID)
	require.Equal(t, "mirror-generic", s.findMirrorForRepository("other").ID)
	require.Nil(t, s.findMirrorForRepository("test"))
}

func Test_findMirrorForRepositoryWithExternal(t *testing.T) {
	s := settings{
		Mirrors: []Mirror{
			{ID: "mirror-generic", MirrorOf: "*, !test"},
			{ID: "mirror-central", MirrorOf: "central"},
		},
	}
	require.Equal(t, "mirror-central", s.findMirrorForRepository("central").ID)
	require.Equal(t, "mirror-generic", s.findMirrorForRepository("other").ID)
	require.Nil(t, s.findMirrorForRepository("test"))
}

func Test_getEffectiveRepositories(t *testing.T) {
	s := settings{
		Profiles: []Profile{
			{
				ID: "p1",
				Repositories: []repository{
					{
						ID:        "r1-releases",
						URL:       "http://repo1",
						Releases:  repositoryPolicy{Enabled: "true"},
						Snapshots: repositoryPolicy{Enabled: "false"},
					},
					{
						ID:        "r2-snapshots",
						URL:       "http://repo2",
						Releases:  repositoryPolicy{Enabled: "false"},
						Snapshots: repositoryPolicy{Enabled: "true"},
					},
				},
			},
			{
				ID: "p2",
				Repositories: []repository{
					{
						ID:        "r3-releases",
						URL:       "http://repo3",
						Releases:  repositoryPolicy{Enabled: "true"},
						Snapshots: repositoryPolicy{Enabled: "false"},
					},
					{
						ID:        "r4-snapshots",
						URL:       "http://repo4",
						Releases:  repositoryPolicy{Enabled: "false"},
						Snapshots: repositoryPolicy{Enabled: "true"},
					},
				},
			},
			{
				ID: "p4",
				Repositories: []repository{
					{
						ID:        "r5-releases",
						URL:       "http://repo5",
						Releases:  repositoryPolicy{Enabled: "true"},
						Snapshots: repositoryPolicy{Enabled: "false"},
					},
					{
						ID:        "r1-releases",
						URL:       "http://repo1-duplicate",
						Releases:  repositoryPolicy{Enabled: "true"},
						Snapshots: repositoryPolicy{Enabled: "false"},
					},
				},
				Activation: activation{ActiveByDefault: true},
			},
		},
		ActiveProfiles: []string{"p1"},
		Mirrors: []Mirror{
			{
				ID:       "mirror-r1-releases",
				MirrorOf: "r1-releases",
				URL:      "http://mirror1",
			},
			{
				ID:       "mirror-external",
				MirrorOf: "external:*",
				URL:      "http://mirror-external",
			},
		},
	}

	effective := s.getEffectiveRepositories()
	require.Len(t, effective, 3)

	require.Equal(t, "r1-releases", effective[0].ID)
	require.Equal(t, "http://mirror1", effective[0].URL)
	require.True(t, getRepositoryPolicy(effective[0].Releases.Enabled, nil))
	require.True(t, getRepositoryPolicy(effective[0].Snapshots.Enabled, nil))

	require.Equal(t, "r2-snapshots", effective[1].ID)
	require.Equal(t, "http://mirror-external", effective[1].URL)
	require.True(t, getRepositoryPolicy(effective[1].Releases.Enabled, nil))
	require.True(t, getRepositoryPolicy(effective[1].Snapshots.Enabled, nil))

	require.Equal(t, "r5-releases", effective[2].ID)
	require.Equal(t, "http://mirror-external", effective[2].URL)
	require.True(t, getRepositoryPolicy(effective[2].Releases.Enabled, nil))
	require.True(t, getRepositoryPolicy(effective[2].Snapshots.Enabled, nil))
}
