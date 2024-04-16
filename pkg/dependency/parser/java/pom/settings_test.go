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
