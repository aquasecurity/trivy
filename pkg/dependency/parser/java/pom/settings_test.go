package pom

import (
	"net/url"
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
								ID:               "mycompany-internal-releases",
								URL:              "https://mycompany.example.com/repository/internal-releases",
								ReleasesEnabled:  "",
								SnapshotsEnabled: "false",
							},
							{
								ID:               "mycompany-global-releases",
								URL:              "https://mycompany.example.com/repository/global-releases",
								ReleasesEnabled:  "true",
								SnapshotsEnabled: "false",
							},
						},
						ActiveByDefault: false,
					},
					{
						ID: "default",
						Repositories: []pomRepository{
							{
								ID:               "mycompany-default-releases",
								URL:              "https://mycompany.example.com/repository/default-releases",
								ReleasesEnabled:  "true",
								SnapshotsEnabled: "false",
							},
						},
						ActiveByDefault: true,
					},
				},
				ActiveProfiles: []string{},
				Proxies:        []Proxy{},
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
								ID:               "mycompany-releases",
								URL:              "https://mycompany.example.com/repository/user-releases",
								ReleasesEnabled:  "true",
								SnapshotsEnabled: "false",
							},
							{
								ID:               "mycompany-user-snapshots",
								URL:              "https://mycompany.example.com/repository/user-snapshots",
								ReleasesEnabled:  "false",
								SnapshotsEnabled: "true",
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
			// [INFO] ------------------< org.apache.maven:standalone-pom >-------------------
			// [INFO] --- maven-help-plugin:3.4.0:effective-settings (default-cli) @ standalone-pom ---
			// Effective user-specific configuration settings:
			//
			// <?xml version="1.0" encoding="UTF-8"?>
			// <settings xmlns="http://maven.apache.org/SETTINGS/1.1.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.1.0 http://maven.apache.org/xsd/settings-1.1.0.xsd">
			//  <localRepository>/root/testdata/user/repository</localRepository>
			//   <servers>
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
			//  <profiles>
			//    <profile>
			//      <activation>
			//        <activeByDefault>true</activeByDefault>
			//      </activation>
			//      <repositories>
			//        <repository>
			//          <releases>
			//            <checksumPolicy>fail</checksumPolicy>
			//          </releases>
			//          <snapshots>
			//            <enabled>false</enabled>
			//          </snapshots>
			//          <id>mycompany-releases</id>
			//          <url>https://mycompany.example.com/repository/user-releases</url>
			//        </repository>
			//        <repository>
			//          <releases>
			//            <enabled>false</enabled>
			//          </releases>
			//          <snapshots />
			//          <id>mycompany-user-snapshots</id>
			//          <url>https://mycompany.example.com/repository/user-snapshots</url>
			//        </repository>
			//      </repositories>
			//      <id>mycompany-global</id>
			//    </profile>
			//    <profile>
			//      <activation>
			//        <activeByDefault>true</activeByDefault>
			//      </activation>
			//      <repositories>
			//        <repository>
			//          <releases />
			//          <snapshots>
			//            <enabled>false</enabled>
			//          </snapshots>
			//          <id>mycompany-default-releases</id>
			//          <url>https://mycompany.example.com/repository/default-releases</url>
			//        </repository>
			//      </repositories>
			//    </profile>
			//  </profiles>
			//  <activeProfiles>
			//    <activeProfile>mycompany-global</activeProfile>
			//  </activeProfiles>
			// </settings>
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
								ID:               "mycompany-releases",
								URL:              "https://mycompany.example.com/repository/user-releases",
								ReleasesEnabled:  "true",
								SnapshotsEnabled: "false",
							},
							{
								ID:               "mycompany-user-snapshots",
								URL:              "https://mycompany.example.com/repository/user-snapshots",
								ReleasesEnabled:  "false",
								SnapshotsEnabled: "true",
							},
						},
						ActiveByDefault: true,
					},
					{
						ID: "default",
						Repositories: []pomRepository{
							{
								ID:               "mycompany-default-releases",
								URL:              "https://mycompany.example.com/repository/default-releases",
								ReleasesEnabled:  "true",
								SnapshotsEnabled: "false",
							},
						},
						ActiveByDefault: true,
					},
				},
				ActiveProfiles: []string{
					"mycompany-global",
				},
				Proxies: []Proxy{},
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
				"PROFILE_ID":      "mycompany-global",
				"REPO_ID":         "mycompany-releases",
				"REPO_URL":        "https://mycompany.example.com",
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
				Profiles: []Profile{
					{
						ID: "mycompany-global",
						Repositories: []pomRepository{
							{
								ID:               "mycompany-releases",
								URL:              "https://mycompany.example.com/repository/user-releases",
								ReleasesEnabled:  "true",
								SnapshotsEnabled: "false",
							},
						},
					},
				},
				ActiveProfiles: []string{
					"mycompany-global",
				},
			},
		},
		{
			name: "user settings proxy",
			envs: map[string]string{
				"HOME":       filepath.Join("testdata", "settings", "user-with-proxy"),
				"MAVEN_HOME": "NOT_EXISTING_PATH",
			},
			wantSettings: settings{
				LocalRepository: "testdata/user/repository",
				Proxies: []Proxy{
					{
						ID:            "proxy-http",
						Active:        "true",
						Protocol:      "http",
						Host:          "user.proxy.com",
						Port:          "8080",
						Username:      "user-proxy-user",
						Password:      "user-proxy-pass",
						NonProxyHosts: "localhost|*.internal.com",
					},
				},
			},
		},
		{
			name: "global settings proxy",
			envs: map[string]string{
				"HOME":       "",
				"MAVEN_HOME": filepath.Join("testdata", "settings", "global-with-proxy"),
			},
			wantSettings: settings{
				LocalRepository: "testdata/repository",
				Servers:         []Server{},
				Profiles:        []Profile{},
				ActiveProfiles:  []string{},
				Proxies: []Proxy{
					{
						ID:       "proxy-http",
						Active:   "true",
						Protocol: "http",
						Host:     "foo.proxy.com",
						Port:     "8080",
					},
				},
			},
		},
		{
			name: "user and global proxies - user takes precedence on duplicate ID",
			envs: map[string]string{
				"HOME":       filepath.Join("testdata", "settings", "user-with-proxy"),
				"MAVEN_HOME": filepath.Join("testdata", "settings", "global-with-proxy"),
			},
			wantSettings: settings{
				LocalRepository: "testdata/user/repository",
				Servers:         []Server{},
				Profiles:        []Profile{},
				ActiveProfiles:  []string{},
				Proxies: []Proxy{
					{
						ID:            "proxy-http",
						Active:        "true",
						Protocol:      "http",
						Host:          "user.proxy.com",
						Port:          "8080",
						Username:      "user-proxy-user",
						Password:      "user-proxy-pass",
						NonProxyHosts: "localhost|*.internal.com",
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

func Test_effectiveRepositories(t *testing.T) {
	tests := []struct {
		name string
		s    settings
		want []repository
	}{
		{
			name: "single active profile, reversed order",
			s: settings{
				Servers: []Server{
					{
						ID:       "r1",
						Username: "u",
						Password: "p",
					},
				},
				Profiles: []Profile{
					{
						ID: "p1",
						Repositories: []pomRepository{
							{
								ID:  "r1",
								URL: "https://example.com/repo1",
								// ReleasesEnabled:  "true", Release field is not explicitly set.
								SnapshotsEnabled: "false",
							},
							{
								ID:              "r2",
								URL:             "https://example.com/repo2",
								ReleasesEnabled: "invalid", // invalid value treated as false
								// SnapshotsEnabled: "true", Snapshot field is not explicitly set.
							},
						},
					},
				},
				ActiveProfiles: []string{"p1"},
			},
			want: []repository{
				{
					url:             mustParseURL(t, "https://example.com/repo2"),
					releaseEnabled:  false,
					snapshotEnabled: true,
				},
				{
					url:             mustParseURL(t, "https://u:p@example.com/repo1"),
					releaseEnabled:  true,
					snapshotEnabled: false,
				},
			},
		},
		{
			name: "activeByDefault + activeProfiles with dedup and reverse",
			s: settings{
				Servers: nil,
				Profiles: []Profile{
					{
						ID:              "p1",
						ActiveByDefault: true,
						Repositories: []pomRepository{
							{
								ID:               "dup",
								URL:              "https://p1.example.com/dup",
								ReleasesEnabled:  "true",
								SnapshotsEnabled: "false",
							},
							{
								ID:               "only-p1",
								URL:              "https://p1.example.com/only",
								ReleasesEnabled:  "true",
								SnapshotsEnabled: "true",
							},
						},
					},
					{
						ID: "p2",
						Repositories: []pomRepository{
							{
								ID:               "dup",
								URL:              "https://p2.example.com/dup",
								ReleasesEnabled:  "true",
								SnapshotsEnabled: "true",
							},
						},
					},
				},
				ActiveProfiles: []string{"p2"},
			},
			// Expected order after dedup (keep first occurrence from p1) and reverse:
			// Input order before reverse: [dup(from p1), only-p1, dup(from p2 - removed by dedup)]
			// After reverse: [only-p1, dup(from p1)]
			want: []repository{
				{
					url:             mustParseURL(t, "https://p1.example.com/only"),
					releaseEnabled:  true,
					snapshotEnabled: true,
				},
				{
					url:             mustParseURL(t, "https://p1.example.com/dup"),
					releaseEnabled:  true,
					snapshotEnabled: false,
				},
			},
		},
		{
			name: "disabled repositories are ignored",
			s: settings{
				Profiles: []Profile{
					{
						ID:              "p",
						ActiveByDefault: true,
						Repositories: []pomRepository{
							{
								ID:               "disabled",
								URL:              "https://example.com/disabled",
								ReleasesEnabled:  "false",
								SnapshotsEnabled: "false",
							},
							{
								ID:               "enabled",
								URL:              "https://example.com/enabled",
								ReleasesEnabled:  "true",
								SnapshotsEnabled: "false",
							},
						},
					},
				},
			},
			want: []repository{
				{
					url:             mustParseURL(t, "https://example.com/enabled"),
					releaseEnabled:  true,
					snapshotEnabled: false,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.s.effectiveRepositories()
			require.Equal(t, tt.want, got)
		})
	}
}

// mustParseURL parses a URL and panics on error; handy for test literals
func mustParseURL(t *testing.T, s string) url.URL {
	t.Helper()
	u, err := url.Parse(s)
	require.NoError(t, err)
	return *u
}

func Test_effectiveProxies(t *testing.T) {
	tests := []struct {
		name     string
		s        settings
		protocol string
		hostname string
		want     []Proxy
	}{
		{
			name: "single active proxy",
			s: settings{
				Proxies: []Proxy{
					{
						ID:       "p1",
						Active:   "true",
						Protocol: "http",
						Host:     "proxy1",
						Port:     "8080",
					},
				},
			},
			protocol: "http",
			hostname: "example.com",
			want: []Proxy{
				{
					ID:       "p1",
					Active:   "true",
					Protocol: "http",
					Host:     "proxy1",
					Port:     "8080",
				},
			},
		},
		{
			name: "inactive proxy ignored",
			s: settings{
				Proxies: []Proxy{
					{
						ID:       "p1",
						Active:   "false",
						Protocol: "http",
					},
				},
			},
			protocol: "http",
			hostname: "example.com",
			want:     nil,
		},
		{
			name: "proxy with empty active field (default true)",
			s: settings{
				Proxies: []Proxy{
					{
						ID:       "p1",
						Active:   "",
						Protocol: "http",
						Host:     "proxy1",
					},
				},
			},
			protocol: "http",
			hostname: "example.com",
			want: []Proxy{
				{
					ID:       "p1",
					Active:   "",
					Protocol: "http",
					Host:     "proxy1",
				},
			},
		},
		{
			name: "protocol mismatch",
			s: settings{
				Proxies: []Proxy{
					{
						ID:       "p1",
						Active:   "true",
						Protocol: "https",
					},
				},
			},
			protocol: "http",
			hostname: "example.com",
			want:     nil,
		},
		{
			name: "non proxy host is skipped",
			s: settings{
				Proxies: []Proxy{
					{
						ID:            "p1",
						Active:        "true",
						Protocol:      "http",
						Host:          "proxy1",
						Port:          "8080",
						NonProxyHosts: "localhost|*.example.com",
					},
				},
			},
			protocol: "http",
			hostname: "test.example.com",
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.s.effectiveProxies(tt.protocol, tt.hostname)
			require.Equal(t, tt.want, got)
		})
	}
}
