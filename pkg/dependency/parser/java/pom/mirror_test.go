package pom

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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
			name:     "exact id no match",
			patterns: []string{"central"},
			repoID:   "internal",
			repoURL:  mustParseURL(t, "https://example.com/repo"),
			want:     false,
		},
		{
			name:     "comma-separated ids match",
			patterns: []string{"central", "internal"},
			repoID:   "internal",
			repoURL:  mustParseURL(t, "https://example.com/repo"),
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
			repoID:   "local",
			repoURL:  mustParseURL(t, "file:///tmp/repo"),
			want:     false,
		},
		{
			name:     "external skips localhost",
			patterns: []string{"external:*"},
			repoID:   "local",
			repoURL:  mustParseURL(t, "http://localhost:8081/repo"),
			want:     false,
		},
		{
			name:     "external skips 127.0.0.1",
			patterns: []string{"external:*"},
			repoID:   "local",
			repoURL:  mustParseURL(t, "http://127.0.0.1/repo"),
			want:     false,
		},
		{
			name:     "external skips IPv6 loopback",
			patterns: []string{"external:*"},
			repoID:   "local",
			repoURL:  mustParseURL(t, "http://[::1]/repo"),
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
			repoID:   "local",
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

func Test_resolveMirrors(t *testing.T) {
	tests := []struct {
		name    string
		mirrors []Mirror
		servers []Server
		want    []mirror
	}{
		{
			name: "split, trim and drop empty patterns",
			mirrors: []Mirror{
				{
					ID:       "m1",
					URL:      "https://mirror.example.com/maven2",
					MirrorOf: "  central , , !internal ,",
				},
			},
			want: []mirror{
				{
					id:       "m1",
					patterns: []string{"central", "!internal"},
					url:      mustParseURL(t, "https://mirror.example.com/maven2"),
				},
			},
		},
		{
			name: "credentials embedded from <server> matching mirror id",
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
			want: []mirror{
				{
					id:       "m1",
					patterns: []string{"*"},
					url:      mustParseURL(t, "https://user:pass@mirror.example.com/maven2"),
				},
			},
		},
		{
			name: "server with empty credentials is ignored",
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
					// Password missing — should not embed credentials.
				},
			},
			want: []mirror{
				{
					id:       "m1",
					patterns: []string{"*"},
					url:      mustParseURL(t, "https://mirror.example.com/maven2"),
				},
			},
		},
		{
			name: "server with non-matching id is ignored",
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
			want: []mirror{
				{
					id:       "m1",
					patterns: []string{"*"},
					url:      mustParseURL(t, "https://mirror.example.com/maven2"),
				},
			},
		},
		{
			name: "mirror with empty mirrorOf is dropped",
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
			want: []mirror{
				{
					id:       "m2",
					patterns: []string{"central"},
					url:      mustParseURL(t, "https://other.example.com/maven2"),
				},
			},
		},
		{
			name: "mirror with unparsable URL is dropped",
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
			want: []mirror{
				{
					id:       "ok",
					patterns: []string{"*"},
					url:      mustParseURL(t, "https://mirror.example.com/maven2"),
				},
			},
		},
		{
			name:    "no mirrors yields nil",
			mirrors: nil,
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveMirrors(tt.mirrors, tt.servers)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestParser_mirrorFor(t *testing.T) {
	tests := []struct {
		name    string
		mirrors []mirror
		repo    repository
		want    repository
	}{
		{
			name:    "no mirrors — repository returned unchanged",
			mirrors: nil,
			repo: repository{
				id:             "central",
				url:            mustParseURL(t, "https://repo.maven.apache.org/maven2"),
				releaseEnabled: true,
			},
			want: repository{
				id:             "central",
				url:            mustParseURL(t, "https://repo.maven.apache.org/maven2"),
				releaseEnabled: true,
			},
		},
		{
			name: "no match — repository returned unchanged",
			mirrors: []mirror{
				{
					id:       "m1",
					patterns: []string{"internal"},
					url:      mustParseURL(t, "https://mirror.example.com/maven2"),
				},
			},
			repo: repository{
				id:             "central",
				url:            mustParseURL(t, "https://repo.maven.apache.org/maven2"),
				releaseEnabled: true,
			},
			want: repository{
				id:             "central",
				url:            mustParseURL(t, "https://repo.maven.apache.org/maven2"),
				releaseEnabled: true,
			},
		},
		{
			name: "match by exact id — release/snapshot flags preserved from original repo",
			mirrors: []mirror{
				{
					id:       "m1",
					patterns: []string{"central"},
					url:      mustParseURL(t, "https://mirror.example.com/maven2"),
				},
			},
			repo: repository{
				id:              "central",
				url:             mustParseURL(t, "https://repo.maven.apache.org/maven2"),
				releaseEnabled:  true,
				snapshotEnabled: false,
			},
			want: repository{
				id:              "m1",
				url:             mustParseURL(t, "https://mirror.example.com/maven2"),
				releaseEnabled:  true,
				snapshotEnabled: false,
			},
		},
		{
			name: "credentials from mirror (not original repo) are kept",
			mirrors: []mirror{
				{
					id:       "m1",
					patterns: []string{"*"},
					url:      mustParseURL(t, "https://mirror-user:mirror-pass@mirror.example.com/maven2"),
				},
			},
			repo: repository{
				id:             "central",
				url:            mustParseURL(t, "https://central-user:central-pass@repo.maven.apache.org/maven2"),
				releaseEnabled: true,
			},
			want: repository{
				id:             "m1",
				url:            mustParseURL(t, "https://mirror-user:mirror-pass@mirror.example.com/maven2"),
				releaseEnabled: true,
			},
		},
		{
			name: "first matching mirror wins (no chaining)",
			mirrors: []mirror{
				{
					id:       "first",
					patterns: []string{"*"},
					url:      mustParseURL(t, "https://first.example.com/maven2"),
				},
				{
					id:       "second",
					patterns: []string{"*"},
					url:      mustParseURL(t, "https://second.example.com/maven2"),
				},
			},
			repo: repository{
				id:             "central",
				url:            mustParseURL(t, "https://repo.maven.apache.org/maven2"),
				releaseEnabled: true,
			},
			want: repository{
				id:             "first",
				url:            mustParseURL(t, "https://first.example.com/maven2"),
				releaseEnabled: true,
			},
		},
		{
			name: "exclusion blocks match and falls through to next mirror",
			mirrors: []mirror{
				{
					id:       "first",
					patterns: []string{"*", "!central"},
					url:      mustParseURL(t, "https://first.example.com/maven2"),
				},
				{
					id:       "second",
					patterns: []string{"central"},
					url:      mustParseURL(t, "https://second.example.com/maven2"),
				},
			},
			repo: repository{
				id:             "central",
				url:            mustParseURL(t, "https://repo.maven.apache.org/maven2"),
				releaseEnabled: true,
			},
			want: repository{
				id:             "second",
				url:            mustParseURL(t, "https://second.example.com/maven2"),
				releaseEnabled: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parser{mirrors: tt.mirrors}
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
	// Test_resolveMirrors and TestParser_mirrorFor. Here we only verify the two
	// things that can only be observed end-to-end through HTTP: that mirrorFor is
	// actually applied to the fetch loop, and that mirror credentials reach the
	// remote request as Basic Auth.
	tests := []struct {
		name            string
		mirrorPatterns  []string
		mirrorWithCreds bool
		wantBasicAuth   string
	}{
		{
			name:           "wildcard mirror redirects the fetch to the mirror server",
			mirrorPatterns: []string{"*"},
		},
		{
			name:            "credentials baked into mirror URL are sent as Basic Auth",
			mirrorPatterns:  []string{"*"},
			mirrorWithCreds: true,
			wantBasicAuth:   "mirror-user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mirrorHits, originalHits int
			var gotBasicAuth string

			mirrorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mirrorHits++
				if u, _, ok := r.BasicAuth(); ok {
					gotBasicAuth = u
				}
				_, _ = w.Write([]byte(minimalPOM))
			}))
			defer mirrorServer.Close()

			originalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				originalHits++
				_, _ = w.Write([]byte(minimalPOM))
			}))
			defer originalServer.Close()

			mirrorURL := mirrorServer.URL
			if tt.mirrorWithCreds {
				u, err := url.Parse(mirrorServer.URL)
				require.NoError(t, err)
				u.User = url.UserPassword("mirror-user", "mirror-pass")
				mirrorURL = u.String()
			}
			u, err := url.Parse(mirrorURL)
			require.NoError(t, err)
			mirrors := []mirror{
				{
					id:       "m1",
					patterns: tt.mirrorPatterns,
					url:      *u,
				},
			}

			origURL, err := url.Parse(originalServer.URL)
			require.NoError(t, err)
			pomRepo := repository{
				id:             "central",
				url:            *origURL,
				releaseEnabled: true,
			}

			p := &Parser{
				logger:     log.WithPrefix("pom"),
				mirrors:    mirrors,
				httpClient: http.DefaultClient,
			}

			paths := []string{"com", "example", "example-api", "1.0.0", "example-api-1.0.0.pom"}
			got, err := p.fetchPOMFromRemoteRepositories(t.Context(), paths, false, []repository{pomRepo})
			require.NoError(t, err)
			require.NotNil(t, got)

			require.Equal(t, 1, mirrorHits, "mirror hits")
			require.Equal(t, 0, originalHits, "original hits")
			require.Equal(t, tt.wantBasicAuth, gotBasicAuth, "basic auth user")
		})
	}
}
