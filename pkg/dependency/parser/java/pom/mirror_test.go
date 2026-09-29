package pom

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/log"
)

func Test_mirror_matches(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		repoID   string
		repoURL  url.URL
		want     bool
	}{
		{
			name:     "wildcard matches everything",
			patterns: []string{"*"},
			repoID:   "anything",
			repoURL:  mustParseURL(t, "https://example.com/repo"),
			want:     true,
		},
		{
			name:     "exact id match",
			patterns: []string{"central"},
			repoID:   "central",
			repoURL:  mustParseURL(t, "https://repo.maven.apache.org/maven2"),
			want:     true,
		},
		{
			// Maven's order-sensitive semantics: the exact-id match is terminal,
			// so a later exclusion of the same id never gets evaluated.
			name:     "exact id wins over a later exclusion of the same id",
			patterns: []string{"central", "!central"},
			repoID:   "central",
			repoURL:  mustParseURL(t, "https://repo.maven.apache.org/maven2"),
			want:     true,
		},
		{
			name:     "exclusion after wildcard",
			patterns: []string{"*", "!internal"},
			repoID:   "internal",
			repoURL:  mustParseURL(t, "https://example.com/repo"),
			want:     false,
		},
		{
			name:     "exclusion before wildcard still wins",
			patterns: []string{"!internal", "*"},
			repoID:   "internal",
			repoURL:  mustParseURL(t, "https://example.com/repo"),
			want:     false,
		},
		{
			name:     "wildcard with unrelated exclusion",
			patterns: []string{"*", "!internal"},
			repoID:   "central",
			repoURL:  mustParseURL(t, "https://repo.maven.apache.org/maven2"),
			want:     true,
		},
		{
			name:     "external matches https",
			patterns: []string{"external:*"},
			repoID:   "central",
			repoURL:  mustParseURL(t, "https://repo.maven.apache.org/maven2"),
			want:     true,
		},
		{
			name:     "external skips file scheme",
			patterns: []string{"external:*"},
			repoID:   "my-local",
			repoURL:  mustParseURL(t, "file:///tmp/repo"),
			want:     false,
		},
		{
			name:     "external skips localhost",
			patterns: []string{"external:*"},
			repoID:   "my-local",
			repoURL:  mustParseURL(t, "http://localhost:8081/repo"),
			want:     false,
		},
		{
			name:     "external skips 127.0.0.1",
			patterns: []string{"external:*"},
			repoID:   "my-local",
			repoURL:  mustParseURL(t, "http://127.0.0.1/repo"),
			want:     false,
		},
		{
			name:     "external with exclusion — excluded id is not mirrored",
			patterns: []string{"external:*", "!internal"},
			repoID:   "internal",
			repoURL:  mustParseURL(t, "https://internal.example.com/repo"),
			want:     false,
		},
		{
			name:     "external:http matches http",
			patterns: []string{"external:http:*"},
			repoID:   "legacy",
			repoURL:  mustParseURL(t, "http://example.com/repo"),
			want:     true,
		},
		{
			name:     "external:http does not match https",
			patterns: []string{"external:http:*"},
			repoID:   "central",
			repoURL:  mustParseURL(t, "https://repo.maven.apache.org/maven2"),
			want:     false,
		},
		{
			name:     "external:http does not match localhost",
			patterns: []string{"external:http:*"},
			repoID:   "my-local",
			repoURL:  mustParseURL(t, "http://localhost/repo"),
			want:     false,
		},
		{
			name:     "empty patterns do not match",
			patterns: nil,
			repoID:   "central",
			repoURL:  mustParseURL(t, "https://repo.maven.apache.org/maven2"),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := mirror{patterns: tt.patterns}
			require.Equal(t, tt.want, m.matches(tt.repoID, &tt.repoURL))
		})
	}
}

// Test_resolveMirrors covers resolveMirrors for both sources: settings.xml <mirror>
// entries (pattern splitting, <server> credentials, dropping bad entries) and
// config-file mirrors (key normalization, target order, dropping bad entries).
func Test_resolveMirrors(t *testing.T) {
	tests := []struct {
		name          string
		mirrors       []Mirror
		servers       []Server
		configMirrors map[string][]string
		want          mirrors
	}{
		{
			name: "settings.xml: split, trim and drop empty patterns",
			mirrors: []Mirror{
				{
					ID:       "m1",
					URL:      "https://mirror.example.com/maven2",
					MirrorOf: "  central , , !internal ,",
				},
			},
			want: mirrors{
				settings: []mirror{
					{
						id:       "m1",
						patterns: []string{"central", "!internal"},
						url:      mustParseURL(t, "https://mirror.example.com/maven2"),
					},
				},
			},
		},
		{
			name: "settings.xml: credentials embedded from <server> matching mirror id",
			mirrors: []Mirror{
				{
					ID:       "m1",
					URL:      "https://mirror.example.com/maven2",
					MirrorOf: "*",
				},
			},
			servers: []Server{
				{
					ID:       "m1",
					Username: "user",
					Password: "pass",
				},
			},
			want: mirrors{
				settings: []mirror{
					{
						id:       "m1",
						patterns: []string{"*"},
						url:      mustParseURL(t, "https://user:pass@mirror.example.com/maven2"),
					},
				},
			},
		},
		{
			name: "settings.xml: <server> credentials override userinfo embedded in mirror URL",
			mirrors: []Mirror{
				{
					ID:       "m1",
					URL:      "https://url-user:url-pass@mirror.example.com/maven2",
					MirrorOf: "*",
				},
			},
			servers: []Server{
				{
					ID:       "m1",
					Username: "server-user",
					Password: "server-pass",
				},
			},
			want: mirrors{
				settings: []mirror{
					{
						id:       "m1",
						patterns: []string{"*"},
						url:      mustParseURL(t, "https://server-user:server-pass@mirror.example.com/maven2"),
					},
				},
			},
		},
		{
			name: "settings.xml: server with non-matching id is ignored",
			mirrors: []Mirror{
				{
					ID:       "m1",
					URL:      "https://mirror.example.com/maven2",
					MirrorOf: "*",
				},
			},
			servers: []Server{
				{
					ID:       "other",
					Username: "user",
					Password: "pass",
				},
			},
			want: mirrors{
				settings: []mirror{
					{
						id:       "m1",
						patterns: []string{"*"},
						url:      mustParseURL(t, "https://mirror.example.com/maven2"),
					},
				},
			},
		},
		{
			name: "settings.xml: mirror with empty mirrorOf is dropped",
			mirrors: []Mirror{
				{
					ID:       "m1",
					URL:      "https://mirror.example.com/maven2",
					MirrorOf: "",
				},
				{
					ID:       "m2",
					URL:      "https://other.example.com/maven2",
					MirrorOf: "central",
				},
			},
			want: mirrors{
				settings: []mirror{
					{
						id:       "m2",
						patterns: []string{"central"},
						url:      mustParseURL(t, "https://other.example.com/maven2"),
					},
				},
			},
		},
		{
			name: "settings.xml: mirror with unparsable URL is dropped",
			mirrors: []Mirror{
				{
					ID:       "broken",
					URL:      "http://[::1",
					MirrorOf: "*",
				},
				{
					ID:       "ok",
					URL:      "https://mirror.example.com/maven2",
					MirrorOf: "*",
				},
			},
			want: mirrors{
				settings: []mirror{
					{
						id:       "ok",
						patterns: []string{"*"},
						url:      mustParseURL(t, "https://mirror.example.com/maven2"),
					},
				},
			},
		},
		{
			name: "no input yields empty mirrors",
			want: mirrors{},
		},
		{
			name: "config file: key normalized (trailing slash trimmed), targets kept in order",
			configMirrors: map[string][]string{
				"https://repo.example.com/maven2/": {
					"https://m1.example.com/maven2",
					"https://m2.example.com/maven2",
				},
			},
			want: mirrors{
				configFile: map[string][]url.URL{
					"https://repo.example.com/maven2": {
						mustParseURL(t, "https://m1.example.com/maven2"),
						mustParseURL(t, "https://m2.example.com/maven2"),
					},
				},
			},
		},
		{
			name: "config file: entry with only an unparsable target is dropped",
			configMirrors: map[string][]string{
				"https://repo.example.com/maven2": {"http://[::1"},
			},
			want: mirrors{},
		},
		{
			name: "config file: unparsable target is dropped, valid ones kept",
			configMirrors: map[string][]string{
				"https://repo.example.com/maven2": {"http://[::1", "https://ok.example.com/maven2"},
			},
			want: mirrors{
				configFile: map[string][]url.URL{
					"https://repo.example.com/maven2": {mustParseURL(t, "https://ok.example.com/maven2")},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, resolveMirrors(tt.mirrors, tt.servers, tt.configMirrors))
		})
	}
}

// TestParser_mirrorFor covers both passes of mirrorFor: matching settings.xml
// <mirror> entries, and applying the config-file mirrors on top of the result —
// including cross-source chaining and fallback lists.
func TestParser_mirrorFor(t *testing.T) {
	tests := []struct {
		name            string
		settingsMirrors []Mirror
		servers         []Server
		configMirrors   map[string][]string
		repo            repository
		want            []repository
	}{
		{
			name: "settings.xml: no match — repository returned unchanged",
			settingsMirrors: []Mirror{
				{ID: "m1", MirrorOf: "internal", URL: "https://mirror.example.com/maven2"},
			},
			repo: repository{
				id:             "central",
				url:            mustParseURL(t, "https://repo.maven.apache.org/maven2"),
				releaseEnabled: true,
			},
			want: []repository{
				{
					id:             "central",
					url:            mustParseURL(t, "https://repo.maven.apache.org/maven2"),
					releaseEnabled: true,
				},
			},
		},
		{
			name: "settings.xml: match by exact id — release/snapshot flags preserved",
			settingsMirrors: []Mirror{
				{ID: "m1", MirrorOf: "central", URL: "https://mirror.example.com/maven2"},
			},
			repo: repository{
				id:              "central",
				url:             mustParseURL(t, "https://repo.maven.apache.org/maven2"),
				releaseEnabled:  true,
				snapshotEnabled: false,
			},
			want: []repository{
				{
					id:              "m1",
					url:             mustParseURL(t, "https://mirror.example.com/maven2"),
					releaseEnabled:  true,
					snapshotEnabled: false,
				},
			},
		},
		{
			name: "settings.xml: mirror credentials (not the original repo's) are kept",
			settingsMirrors: []Mirror{
				{ID: "m1", MirrorOf: "*", URL: "https://mirror-user:mirror-pass@mirror.example.com/maven2"},
			},
			repo: repository{
				id:             "central",
				url:            mustParseURL(t, "https://central-user:central-pass@repo.maven.apache.org/maven2"),
				releaseEnabled: true,
			},
			want: []repository{
				{
					id:             "m1",
					url:            mustParseURL(t, "https://mirror-user:mirror-pass@mirror.example.com/maven2"),
					releaseEnabled: true,
				},
			},
		},
		{
			name: "settings.xml: first matching mirror wins",
			settingsMirrors: []Mirror{
				{ID: "first", MirrorOf: "*", URL: "https://first.example.com/maven2"},
				{ID: "second", MirrorOf: "*", URL: "https://second.example.com/maven2"},
			},
			repo: repository{
				id:             "central",
				url:            mustParseURL(t, "https://repo.maven.apache.org/maven2"),
				releaseEnabled: true,
			},
			want: []repository{
				{
					id:             "first",
					url:            mustParseURL(t, "https://first.example.com/maven2"),
					releaseEnabled: true,
				},
			},
		},
		{
			name: "settings.xml: exclusion blocks match, falls through to next mirror",
			settingsMirrors: []Mirror{
				{ID: "first", MirrorOf: "*,!central", URL: "https://first.example.com/maven2"},
				{ID: "second", MirrorOf: "central", URL: "https://second.example.com/maven2"},
			},
			repo: repository{
				id:             "central",
				url:            mustParseURL(t, "https://repo.maven.apache.org/maven2"),
				releaseEnabled: true,
			},
			want: []repository{
				{
					id:             "second",
					url:            mustParseURL(t, "https://second.example.com/maven2"),
					releaseEnabled: true,
				},
			},
		},
		{
			name: "config file: single mirror — repo1 -> repo3",
			configMirrors: map[string][]string{
				"https://repo1.example.com/maven2": {"https://repo3.example.com/maven2"},
			},
			repo: repository{
				id:             "central",
				url:            mustParseURL(t, "https://repo1.example.com/maven2"),
				releaseEnabled: true,
			},
			want: []repository{
				{
					id:             "central",
					url:            mustParseURL(t, "https://repo3.example.com/maven2"),
					releaseEnabled: true,
				},
			},
		},
		{
			name: "config file: trailing slash in key still matches",
			configMirrors: map[string][]string{
				"https://repo1.example.com/maven2/": {"https://repo3.example.com/maven2"},
			},
			repo: repository{
				id:             "central",
				url:            mustParseURL(t, "https://repo1.example.com/maven2"),
				releaseEnabled: true,
			},
			want: []repository{
				{
					id:             "central",
					url:            mustParseURL(t, "https://repo3.example.com/maven2"),
					releaseEnabled: true,
				},
			},
		},
		{
			// Trivy embeds <server> credentials into the repository URL, so the lookup
			// must ignore them — the configured key never carries a password.
			name: "config file: repository credentials are ignored by the lookup",
			configMirrors: map[string][]string{
				"https://repo1.example.com/maven2": {"https://repo3.example.com/maven2"},
			},
			repo: repository{
				id:             "corp",
				url:            mustParseURL(t, "https://repo-user:repo-pass@repo1.example.com/maven2"),
				releaseEnabled: true,
			},
			want: []repository{
				{
					id:             "corp",
					url:            mustParseURL(t, "https://repo3.example.com/maven2"),
					releaseEnabled: true,
				},
			},
		},
		{
			// The path is cleaned, so repeated and relative segments don't break the match.
			name: "config file: path segments are cleaned before the lookup",
			configMirrors: map[string][]string{
				"https://repo1.example.com//nexus/./content/../maven2/": {"https://repo3.example.com/maven2"},
			},
			repo: repository{
				id:             "central",
				url:            mustParseURL(t, "https://repo1.example.com/nexus/maven2"),
				releaseEnabled: true,
			},
			want: []repository{
				{
					id:             "central",
					url:            mustParseURL(t, "https://repo3.example.com/maven2"),
					releaseEnabled: true,
				},
			},
		},
		{
			// RFC 3986 defines the host as case-insensitive, unlike the path.
			name: "config file: host case is ignored by the lookup",
			configMirrors: map[string][]string{
				"https://Repo1.Example.COM/maven2": {"https://repo3.example.com/maven2"},
			},
			repo: repository{
				id:             "central",
				url:            mustParseURL(t, "https://repo1.example.com/maven2"),
				releaseEnabled: true,
			},
			want: []repository{
				{
					id:             "central",
					url:            mustParseURL(t, "https://repo3.example.com/maven2"),
					releaseEnabled: true,
				},
			},
		},
		{
			// Several mirrors for one repository become ordered fallback candidates.
			name: "config file: fallback list — repo1 -> [repo3, repo4] in order",
			configMirrors: map[string][]string{
				"https://repo1.example.com/maven2": {
					"https://repo3.example.com/maven2",
					"https://repo4.example.com/maven2",
				},
			},
			repo: repository{
				id:             "central",
				url:            mustParseURL(t, "https://repo1.example.com/maven2"),
				releaseEnabled: true,
			},
			want: []repository{
				{
					id:             "central",
					url:            mustParseURL(t, "https://repo3.example.com/maven2"),
					releaseEnabled: true,
				},
				{
					id:             "central",
					url:            mustParseURL(t, "https://repo4.example.com/maven2"),
					releaseEnabled: true,
				},
			},
		},
		{
			// Example 1 from the spec: both sources target repo1; settings.xml wins
			// because it rewrites the URL first and the config pass no longer matches.
			name: "cross-source: conflict on the same key — settings.xml wins",
			settingsMirrors: []Mirror{
				{ID: "settings-mirror", MirrorOf: "central", URL: "https://repo2.example.com/maven2"},
			},
			configMirrors: map[string][]string{
				"https://repo1.example.com/maven2": {"https://repo3.example.com/maven2"},
			},
			repo: repository{
				id:             "central",
				url:            mustParseURL(t, "https://repo1.example.com/maven2"),
				releaseEnabled: true,
			},
			want: []repository{
				{
					id:             "settings-mirror",
					url:            mustParseURL(t, "https://repo2.example.com/maven2"),
					releaseEnabled: true,
				},
			},
		},
		{
			// Example 2 from the spec: cross-source chaining.
			// settings.xml repo1 -> repo2, trivy.yaml repo2 -> repo3 => repo1 -> repo3.
			name: "cross-source: chaining — repo1 --settings--> repo2 --trivy.yaml--> repo3",
			settingsMirrors: []Mirror{
				{ID: "settings-mirror", MirrorOf: "central", URL: "https://repo2.example.com/maven2"},
			},
			configMirrors: map[string][]string{
				"https://repo2.example.com/maven2": {"https://repo3.example.com/maven2"},
			},
			repo: repository{
				id:             "central",
				url:            mustParseURL(t, "https://repo1.example.com/maven2"),
				releaseEnabled: true,
			},
			want: []repository{
				{
					id:             "settings-mirror",
					url:            mustParseURL(t, "https://repo3.example.com/maven2"),
					releaseEnabled: true,
				},
			},
		},
		{
			// Chaining through a mirror that has <server> credentials: pass 1 rewrites the
			// repository to the mirror URL with the credentials embedded, so the config-file
			// lookup in pass 2 sees them and must still match the plain configured key.
			name: "cross-source: chaining through a mirror with credentials",
			settingsMirrors: []Mirror{
				{ID: "settings-mirror", MirrorOf: "central", URL: "https://repo2.example.com/maven2"},
			},
			servers: []Server{
				{ID: "settings-mirror", Username: "mirror-user", Password: "mirror-pass"},
			},
			configMirrors: map[string][]string{
				"https://repo2.example.com/maven2": {"https://repo3.example.com/maven2"},
			},
			repo: repository{
				id:             "central",
				url:            mustParseURL(t, "https://repo1.example.com/maven2"),
				releaseEnabled: true,
			},
			want: []repository{
				{
					id:             "settings-mirror",
					url:            mustParseURL(t, "https://repo3.example.com/maven2"),
					releaseEnabled: true,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parser{mirrors: resolveMirrors(tt.settingsMirrors, tt.servers, tt.configMirrors)}
			require.Equal(t, tt.want, p.mirrorFor(tt.repo))
		})
	}
}

// Test_fetchPOMFromRemoteRepositories_mirror verifies that mirrors substitute
// the target URL inside fetchPOMFromRemoteRepositories — i.e. that mirrorFor
// is wired into the fetch loop, not just the matching logic.
func Test_fetchPOMFromRemoteRepositories_mirror(t *testing.T) {
	const minimalPOM = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>example-api</artifactId>
  <version>1.0.0</version>
</project>`

	// Matching logic and credential resolution are covered by Test_mirror_matches,
	// Test_resolveMirrors and TestParser_mirrorFor. Here we verify the things that
	// can only be observed end-to-end through HTTP: that mirrorFor is applied to the
	// fetch loop, that mirror credentials reach the remote request as Basic Auth, that
	// a settings.xml -> trivy.yaml chain routes the fetch through to the final mirror,
	// that the fetch falls back to the next trivy.yaml mirror on 404 or 429, and that a
	// 429 is returned only when every mirror is rate-limited.
	tests := []struct {
		name            string
		mirrorPatterns  []string
		mirrorWithCreds bool
		wantBasicAuth   string
		configMirrors   map[string][]string // trivy.yaml mirrors, by server role: source-role -> []mirror-role
		wantHits        map[string]int      // expected request count per server role
		wantErr         string              // non-empty: fetch must fail with an error containing this
	}{
		{
			name:            "settings.xml <server> credentials reach the mirror as Basic Auth",
			mirrorPatterns:  []string{"*"},
			mirrorWithCreds: true,
			wantBasicAuth:   "mirror-user",
			wantHits:        map[string]int{"mirror": 1},
		},
		{
			// Example 2 end-to-end: settings.xml rewrites central(repo1) -> mirror(repo2),
			// then trivy.yaml rewrites repo2 -> chain(repo3), so only repo3 is requested.
			name:           "cross-source chaining: settings.xml then trivy.yaml routes to the final mirror",
			mirrorPatterns: []string{"*"},
			configMirrors:  map[string][]string{"mirror": {"chain"}},
			wantHits:       map[string]int{"chain": 1},
		},
		{
			// trivy.yaml lists two mirrors for repo2; the first 404s, so the fetch falls
			// back to the second and succeeds there.
			name:           "trivy.yaml fallback: first mirror 404s, second one serves",
			mirrorPatterns: []string{"*"},
			configMirrors:  map[string][]string{"mirror": {"dead", "chain"}},
			wantHits:       map[string]int{"dead": 1, "chain": 1},
		},
		{
			// The first mirror returns 429; the fetch skips it and succeeds on the second.
			name:           "trivy.yaml fallback: first mirror 429s, second one serves",
			mirrorPatterns: []string{"*"},
			configMirrors:  map[string][]string{"mirror": {"limited", "chain"}},
			wantHits:       map[string]int{"limited": 1, "chain": 1},
		},
		{
			// Every mirror is rate-limited; the 429 is returned rather than "not found".
			name:           "all mirrors rate-limited: the 429 is returned",
			mirrorPatterns: []string{"*"},
			configMirrors:  map[string][]string{"mirror": {"limited"}},
			wantHits:       map[string]int{"limited": 1},
			wantErr:        "429",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hits := make(map[string]int)
			var gotBasicAuth string

			// newServer registers an HTTP server for a role. status 200 serves the POM;
			// any other status (e.g. 404 or 429) makes the fetch fall back to the next candidate.
			newServer := func(role string, status int) *httptest.Server {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits[role]++
					if u, _, ok := r.BasicAuth(); ok {
						gotBasicAuth = u
					}
					if status != http.StatusOK {
						w.WriteHeader(status)
						return
					}
					_, _ = w.Write([]byte(minimalPOM))
				}))
				t.Cleanup(s.Close)
				return s
			}

			// repo1: original repository; mirror: settings.xml target; chain/dead:
			// trivy.yaml targets (dead always 404s).
			servers := map[string]*httptest.Server{
				"repo1":   newServer("repo1", http.StatusOK),
				"mirror":  newServer("mirror", http.StatusOK),
				"chain":   newServer("chain", http.StatusOK),
				"dead":    newServer("dead", http.StatusNotFound),
				"limited": newServer("limited", http.StatusTooManyRequests),
			}

			// trivy.yaml mirrors: resolve role names to server URLs.
			configFileMirrors := make(map[string][]string)
			for srcRole, dstRoles := range tt.configMirrors {
				for _, dstRole := range dstRoles {
					src := servers[srcRole].URL
					configFileMirrors[src] = append(configFileMirrors[src], servers[dstRole].URL)
				}
			}

			// settings.xml mirror central -> "mirror"; creds (if any) come from a <server>.
			var srvCreds []Server
			if tt.mirrorWithCreds {
				srvCreds = []Server{{ID: "m1", Username: "mirror-user", Password: "mirror-pass"}}
			}
			resolved := resolveMirrors(
				[]Mirror{{ID: "m1", URL: servers["mirror"].URL, MirrorOf: strings.Join(tt.mirrorPatterns, ",")}},
				srvCreds,
				configFileMirrors,
			)

			origURL, err := url.Parse(servers["repo1"].URL)
			require.NoError(t, err)
			pomRepo := repository{id: "central", url: *origURL, releaseEnabled: true}

			p := &Parser{
				logger:     log.WithPrefix("pom"),
				mirrors:    resolved,
				httpClient: http.DefaultClient,
			}

			paths := []string{"com", "example", "example-api", "1.0.0", "example-api-1.0.0.pom"}
			got, err := p.fetchPOMFromRemoteRepositories(t.Context(), paths, false, []repository{pomRepo})
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, got)
			}

			for role := range servers {
				require.Equal(t, tt.wantHits[role], hits[role], "request count for %q", role)
			}
			require.Equal(t, tt.wantBasicAuth, gotBasicAuth, "basic auth user")
		})
	}
}
