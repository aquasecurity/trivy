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
				Profiles: []Profile{
					{
						ID: "mycompany-global",
						Repositories: []pomRepository{
							{
								ID:  "mycompany-internal-releases",
								URL: "https://mycompany.example.com/repository/internal-releases",
								Releases: struct {
									Enabled string `xml:"enabled"`
								}{
									Enabled: "true",
								},
								Snapshots: struct {
									Enabled string `xml:"enabled"`
								}{
									Enabled: "false",
								},
							},
							{
								ID:  "mycompany-global-releases",
								URL: "https://mycompany.example.com/repository/global-releases",
								Releases: struct {
									Enabled string `xml:"enabled"`
								}{
									Enabled: "true",
								},
								Snapshots: struct {
									Enabled string `xml:"enabled"`
								}{
									Enabled: "false",
								},
							},
						},
						ActiveByDefault: false,
					},
					{
						ID: "default",
						Repositories: []pomRepository{
							{
								ID:  "mycompany-default-releases",
								URL: "https://mycompany.example.com/repository/default-releases",
								Releases: struct {
									Enabled string `xml:"enabled"`
								}{
									Enabled: "true",
								},
								Snapshots: struct {
									Enabled string `xml:"enabled"`
								}{
									Enabled: "false",
								},
							},
						},
						ActiveByDefault: true,
					},
				},
				ActiveProfiles: []string{},
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
				Profiles: []Profile{
					{
						ID: "mycompany-global",
						Repositories: []pomRepository{
							{
								ID:  "mycompany-releases",
								URL: "https://mycompany.example.com/repository/user-releases",
								Releases: struct {
									Enabled string `xml:"enabled"`
								}{
									Enabled: "true",
								},
								Snapshots: struct {
									Enabled string `xml:"enabled"`
								}{
									Enabled: "false",
								},
							},
							{
								ID:  "mycompany-user-snapshots",
								URL: "https://mycompany.example.com/repository/user-snapshots",
								Releases: struct {
									Enabled string `xml:"enabled"`
								}{
									Enabled: "false",
								},
								Snapshots: struct {
									Enabled string `xml:"enabled"`
								}{
									Enabled: "true",
								},
							},
						},
						ActiveByDefault: true,
					},
				},
				ActiveProfiles: []string{
					"mycompany-global",
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
				Profiles: []Profile{
					{
						ID: "mycompany-global",
						Repositories: []pomRepository{
							{
								ID:  "mycompany-releases",
								URL: "https://mycompany.example.com/repository/user-releases",
								Releases: struct {
									Enabled string `xml:"enabled"`
								}{
									Enabled: "true",
								},
								Snapshots: struct {
									Enabled string `xml:"enabled"`
								}{
									Enabled: "false",
								},
							},
							{
								ID:  "mycompany-user-snapshots",
								URL: "https://mycompany.example.com/repository/user-snapshots",
								Releases: struct {
									Enabled string `xml:"enabled"`
								}{
									Enabled: "false",
								},
								Snapshots: struct {
									Enabled string `xml:"enabled"`
								}{
									Enabled: "true",
								},
							},
						},
						ActiveByDefault: true,
					},
					{
						ID: "default",
						Repositories: []pomRepository{
							{
								ID:  "mycompany-default-releases",
								URL: "https://mycompany.example.com/repository/default-releases",
								Releases: struct {
									Enabled string `xml:"enabled"`
								}{
									Enabled: "true",
								},
								Snapshots: struct {
									Enabled string `xml:"enabled"`
								}{
									Enabled: "false",
								},
							},
						},
						ActiveByDefault: true,
					},
				},
				ActiveProfiles: []string{
					"mycompany-global",
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
			// TODO - add placeholders for profiles
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
