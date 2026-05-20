package pom

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_mirror_matches(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		repoID   string
		repoURL  string
		want     bool
	}{
		{
			name:     "wildcard matches everything",
			patterns: []string{"*"},
			repoID:   "anything",
			repoURL:  "https://example.com/repo",
			want:     true,
		},
		{
			name:     "exact id match",
			patterns: []string{"central"},
			repoID:   "central",
			repoURL:  "https://repo.maven.apache.org/maven2",
			want:     true,
		},
		{
			name:     "exact id no match",
			patterns: []string{"central"},
			repoID:   "internal",
			repoURL:  "https://example.com/repo",
			want:     false,
		},
		{
			name:     "comma-separated ids match",
			patterns: []string{"central", "internal"},
			repoID:   "internal",
			repoURL:  "https://example.com/repo",
			want:     true,
		},
		{
			name:     "exclusion after wildcard",
			patterns: []string{"*", "!internal"},
			repoID:   "internal",
			repoURL:  "https://example.com/repo",
			want:     false,
		},
		{
			name:     "exclusion before wildcard still wins",
			patterns: []string{"!internal", "*"},
			repoID:   "internal",
			repoURL:  "https://example.com/repo",
			want:     false,
		},
		{
			name:     "wildcard with unrelated exclusion",
			patterns: []string{"*", "!internal"},
			repoID:   "central",
			repoURL:  "https://repo.maven.apache.org/maven2",
			want:     true,
		},
		{
			name:     "external matches https",
			patterns: []string{"external:*"},
			repoID:   "central",
			repoURL:  "https://repo.maven.apache.org/maven2",
			want:     true,
		},
		{
			name:     "external skips file scheme",
			patterns: []string{"external:*"},
			repoID:   "local",
			repoURL:  "file:///tmp/repo",
			want:     false,
		},
		{
			name:     "external skips localhost",
			patterns: []string{"external:*"},
			repoID:   "local",
			repoURL:  "http://localhost:8081/repo",
			want:     false,
		},
		{
			name:     "external skips 127.0.0.1",
			patterns: []string{"external:*"},
			repoID:   "local",
			repoURL:  "http://127.0.0.1/repo",
			want:     false,
		},
		{
			name:     "external skips IPv6 loopback",
			patterns: []string{"external:*"},
			repoID:   "local",
			repoURL:  "http://[::1]/repo",
			want:     false,
		},
		{
			name:     "external:http matches http",
			patterns: []string{"external:http:*"},
			repoID:   "legacy",
			repoURL:  "http://example.com/repo",
			want:     true,
		},
		{
			name:     "external:http does not match https",
			patterns: []string{"external:http:*"},
			repoID:   "central",
			repoURL:  "https://repo.maven.apache.org/maven2",
			want:     false,
		},
		{
			name:     "external:http does not match localhost",
			patterns: []string{"external:http:*"},
			repoID:   "local",
			repoURL:  "http://localhost/repo",
			want:     false,
		},
		{
			name:     "empty patterns do not match",
			patterns: nil,
			repoID:   "central",
			repoURL:  "https://repo.maven.apache.org/maven2",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := mirror{patterns: tt.patterns}
			require.Equal(t, tt.want, m.matches(tt.repoID, tt.repoURL))
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

func Test_isExternalRepo(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"https external", "https://example.com/repo", true},
		{"http external", "http://example.com/repo", true},
		{"file scheme", "file:///tmp/repo", false},
		{"localhost", "http://localhost:8081/repo", false},
		{"127.0.0.1", "http://127.0.0.1/repo", false},
		{"IPv6 loopback", "http://[::1]/repo", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			require.NoError(t, err)
			require.Equal(t, tt.want, isExternalRepo(u))
		})
	}
}
