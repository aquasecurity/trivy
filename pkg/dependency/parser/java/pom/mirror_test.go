package pom

import (
	"bytes"
	"cmp"
	"fmt"
	"log/slog"
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
	// Matching logic and credential resolution are covered by Test_mirror_matches,
	// Test_resolveMirrors and TestParser_mirrorFor. Here we verify the things that
	// can only be observed end-to-end through HTTP: that mirrorFor is applied to the
	// fetch loop, that mirror credentials reach the remote request as Basic Auth, that
	// a settings.xml -> trivy.yaml chain routes the fetch through to the final mirror,
	// that the fetch falls back to the next trivy.yaml mirror on 404 or 429, that a
	// 429 is returned only when every mirror is rate-limited, and that rejected
	// credentials are warned about once per repository, for both the POM and
	// maven-metadata.xml requests.
	tests := []struct {
		name           string
		mirrors        fetchMirrorSetup
		snapshot       bool // fetch a snapshot artifact, which requests maven-metadata.xml first
		parserCount    int  // parsers (pom.xml files) fetching the POM; 1 if zero
		wantBasicAuth  string
		wantHits       map[string]int // expected request count per server role
		wantErr        string         // non-empty: fetch must fail with an error containing this
		wantWarnStatus []int          // status codes of the expected warnings, one per repository
	}{
		{
			name: "settings.xml <server> credentials reach the mirror as Basic Auth",
			mirrors: fetchMirrorSetup{
				patterns:  []string{"*"},
				withCreds: true,
			},
			wantBasicAuth: "mirror-user",
			wantHits:      map[string]int{"mirror": 1},
		},
		{
			// Example 2 end-to-end: settings.xml rewrites central(repo1) -> mirror(repo2),
			// then trivy.yaml rewrites repo2 -> chain(repo3), so only repo3 is requested.
			name: "cross-source chaining: settings.xml then trivy.yaml routes to the final mirror",
			mirrors: fetchMirrorSetup{
				patterns: []string{"*"},
				config:   map[string][]string{"mirror": {"chain"}},
			},
			wantHits: map[string]int{"chain": 1},
		},
		{
			// trivy.yaml lists two mirrors for repo2; the first 404s, so the fetch falls
			// back to the second and succeeds there.
			name: "trivy.yaml fallback: first mirror 404s, second one serves",
			mirrors: fetchMirrorSetup{
				patterns: []string{"*"},
				config:   map[string][]string{"mirror": {"dead", "chain"}},
			},
			wantHits: map[string]int{"dead": 1, "chain": 1},
		},
		{
			// The first mirror returns 429; the fetch skips it and succeeds on the second.
			name: "trivy.yaml fallback: first mirror 429s, second one serves",
			mirrors: fetchMirrorSetup{
				patterns: []string{"*"},
				config:   map[string][]string{"mirror": {"limited", "chain"}},
			},
			wantHits: map[string]int{"limited": 1, "chain": 1},
		},
		{
			// Every mirror is rate-limited; the 429 is returned rather than "not found".
			name: "all mirrors rate-limited: the 429 is returned",
			mirrors: fetchMirrorSetup{
				patterns: []string{"*"},
				config:   map[string][]string{"mirror": {"limited"}},
			},
			wantHits: map[string]int{"limited": 1},
			wantErr:  "429",
		},
		{
			// Both parsers hit the mirror, but the warning is logged once.
			name: "401 with credentials: warned once per repository across parsers",
			mirrors: fetchMirrorSetup{
				patterns:  []string{"*"},
				withCreds: true,
				role:      "unauthorized",
			},
			parserCount:    2,
			wantBasicAuth:  "mirror-user",
			wantHits:       map[string]int{"unauthorized": 2},
			wantErr:        "not found",
			wantWarnStatus: []int{http.StatusUnauthorized},
		},
		{
			name: "403 with credentials: warned, without the URL query",
			mirrors: fetchMirrorSetup{
				patterns:  []string{"*"},
				withCreds: true,
				role:      "forbidden",
				query:     "?token=secret-token",
			},
			wantBasicAuth:  "mirror-user",
			wantHits:       map[string]int{"forbidden": 1},
			wantErr:        "not found",
			wantWarnStatus: []int{http.StatusForbidden},
		},
		{
			// The same status on maven-metadata.xml is warned about too; the POM is then served.
			name: "401 on maven-metadata.xml with credentials: warned",
			mirrors: fetchMirrorSetup{
				patterns:  []string{"*"},
				withCreds: true,
				role:      "metadata-unauthorized",
			},
			snapshot:       true,
			wantBasicAuth:  "mirror-user",
			wantHits:       map[string]int{"metadata-unauthorized": 2},
			wantWarnStatus: []int{http.StatusUnauthorized},
		},
		{
			name: "different repositories are warned about separately",
			mirrors: fetchMirrorSetup{
				patterns:  []string{"central"},
				withCreds: true,
				role:      "unauthorized",
				otherRole: "forbidden",
			},
			wantBasicAuth:  "mirror-user",
			wantHits:       map[string]int{"unauthorized": 1, "forbidden": 1},
			wantErr:        "not found",
			wantWarnStatus: []int{http.StatusUnauthorized, http.StatusForbidden},
		},
		{
			name: "404 with credentials: not warned",
			mirrors: fetchMirrorSetup{
				patterns:  []string{"*"},
				withCreds: true,
				role:      "dead",
			},
			wantBasicAuth: "mirror-user",
			wantHits:      map[string]int{"dead": 1},
			wantErr:       "not found",
		},
		{
			name: "401 without credentials: not warned",
			mirrors: fetchMirrorSetup{
				patterns: []string{"*"},
				role:     "unauthorized",
			},
			wantHits: map[string]int{"unauthorized": 1},
			wantErr:  "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetRejectedCredentialsRepos(t)
			srv := startFetchServers(t)
			resolved, repos := tt.mirrors.resolve(t, srv)

			var logs bytes.Buffer
			logger := log.New(log.NewHandler(&logs, &log.Options{Level: slog.LevelWarn}))

			paths := []string{"com", "example", "example-api", "1.0.0", "example-api-1.0.0.pom"}
			// One parser per pom.xml.
			for range cmp.Or(tt.parserCount, 1) {
				p := &Parser{
					logger:     logger,
					mirrors:    resolved,
					httpClient: http.DefaultClient,
				}

				got, err := p.fetchPOMFromRemoteRepositories(t.Context(), paths, tt.snapshot, repos)
				if tt.wantErr != "" {
					require.ErrorContains(t, err, tt.wantErr)
				} else {
					require.NoError(t, err)
					require.NotNil(t, got)
				}
			}

			for role := range srv.byRole {
				require.Equal(t, tt.wantHits[role], srv.hits[role], "request count for %q", role)
			}
			require.Equal(t, tt.wantBasicAuth, srv.basicAuth, "basic auth user")

			assertRejectedCredentialsWarnings(t, logs.String(), tt.wantWarnStatus)
		})
	}
}

const fetchTestPOM = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>example-api</artifactId>
  <version>1.0.0</version>
</project>`

// fetchServers are the HTTP servers of Test_fetchPOMFromRemoteRepositories_mirror, by role.
// Each answers with the status of its role: 200 serves the POM, any other status makes the fetch
// fall back to the next candidate. repo1 is the original repository, mirror the settings.xml
// target, chain and dead the trivy.yaml targets (dead 404s), limited 429s, unauthorized and
// forbidden answer 401 and 403, metadata-unauthorized serves the POM but 401s maven-metadata.xml.
type fetchServers struct {
	byRole    map[string]*httptest.Server
	hits      map[string]int // request count per role
	basicAuth string         // user of the last request that carried Basic Auth
}

func startFetchServers(t *testing.T) *fetchServers {
	t.Helper()

	statuses := map[string]int{
		"repo1":                 http.StatusOK,
		"mirror":                http.StatusOK,
		"chain":                 http.StatusOK,
		"dead":                  http.StatusNotFound,
		"limited":               http.StatusTooManyRequests,
		"unauthorized":          http.StatusUnauthorized,
		"forbidden":             http.StatusForbidden,
		"metadata-unauthorized": http.StatusOK,
	}
	// A role may answer maven-metadata.xml differently from the POM.
	metadataStatuses := map[string]int{"metadata-unauthorized": http.StatusUnauthorized}

	srv := &fetchServers{
		byRole: make(map[string]*httptest.Server, len(statuses)),
		hits:   make(map[string]int),
	}
	for role, status := range statuses {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			srv.hits[role]++
			if u, _, ok := r.BasicAuth(); ok {
				srv.basicAuth = u
			}
			respStatus := status
			if strings.HasSuffix(r.URL.Path, "/maven-metadata.xml") {
				respStatus = cmp.Or(metadataStatuses[role], status)
			}
			if respStatus != http.StatusOK {
				w.WriteHeader(respStatus)
				return
			}
			_, _ = w.Write([]byte(fetchTestPOM))
		}))
		t.Cleanup(s.Close)
		srv.byRole[role] = s
	}
	return srv
}

// fetchMirrorSetup describes the mirrors of Test_fetchPOMFromRemoteRepositories_mirror.
// Servers are referenced by role.
type fetchMirrorSetup struct {
	patterns  []string            // mirrorOf of the settings.xml mirror m1, which serves the repository "central"
	role      string              // server that m1 points to; "mirror" if empty
	query     string              // appended to the URL of m1, e.g. a token
	otherRole string              // if set, mirror m2 serves a second repository "other" from this server
	withCreds bool                // m1 and m2 get credentials from a settings.xml <server>
	config    map[string][]string // trivy.yaml mirrors: source role -> mirror roles
}

// resolve builds the mirrors and the repositories to fetch from.
func (m fetchMirrorSetup) resolve(t *testing.T, srv *fetchServers) (mirrors, []repository) {
	t.Helper()

	configFileMirrors := make(map[string][]string)
	for srcRole, dstRoles := range m.config {
		for _, dstRole := range dstRoles {
			src := srv.byRole[srcRole].URL
			configFileMirrors[src] = append(configFileMirrors[src], srv.byRole[dstRole].URL)
		}
	}

	origURL, err := url.Parse(srv.byRole["repo1"].URL)
	require.NoError(t, err)
	central := repository{id: "central", url: *origURL, releaseEnabled: true, snapshotEnabled: true}

	settingsMirrors := []Mirror{{
		ID:       "m1",
		URL:      srv.byRole[cmp.Or(m.role, "mirror")].URL + m.query,
		MirrorOf: strings.Join(m.patterns, ","),
	}}
	repos := []repository{central}
	if m.otherRole != "" {
		other := central
		other.id = "other"
		repos = append(repos, other)
		settingsMirrors = append(settingsMirrors, Mirror{ID: "m2", URL: srv.byRole[m.otherRole].URL, MirrorOf: "other"})
	}

	var srvCreds []Server
	if m.withCreds {
		srvCreds = []Server{
			{ID: "m1", Username: "mirror-user", Password: "mirror-pass"},
			{ID: "m2", Username: "mirror-user", Password: "mirror-pass"},
		}
	}
	return resolveMirrors(settingsMirrors, srvCreds, configFileMirrors), repos
}

// resetRejectedCredentialsRepos clears the package-level warning state, which is keyed by
// host:port, so that a port reused by the OS for a later case does not suppress its warning.
func resetRejectedCredentialsRepos(t *testing.T) {
	t.Helper()
	rejectedCredentialsRepos.Range(func(key string, _ struct{}) bool {
		rejectedCredentialsRepos.Delete(key)
		return true
	})
}

// assertRejectedCredentialsWarnings checks for exactly one warning per status code
// and that no credentials were logged.
func assertRejectedCredentialsWarnings(t *testing.T, logs string, wantStatuses []int) {
	t.Helper()
	require.Equal(t, len(wantStatuses), strings.Count(logs, "denied access with the configured credentials"), logs)
	for _, status := range wantStatuses {
		require.Contains(t, logs, fmt.Sprintf("statusCode=%d", status))
	}
	require.NotContains(t, logs, "mirror-user", "credentials must not be logged")
	require.NotContains(t, logs, "mirror-pass", "credentials must not be logged")
	require.NotContains(t, logs, "secret-token", "the URL query must not be logged")
}
