package pom

import (
	"net/url"
	"strings"

	"github.com/aquasecurity/trivy/pkg/log"
)

// mirror is the runtime representation of a <mirror> from settings.xml.
// Compared to Mirror, the matching rules are pre-split and the URL is parsed
// with credentials from the matching <server> already embedded, so the hot
// path in mirrorFor only needs to walk patterns and compare strings.
type mirror struct {
	id       string
	patterns []string // trimmed, non-empty entries from <mirrorOf>
	url      url.URL  // parsed URL with userinfo from the matching <server>
}

// resolveMirrors converts <mirror> entries from settings.xml into the runtime
// mirror form: split and trim the mirrorOf patterns, parse the URL, and embed
// credentials from the <server> whose id equals the mirror id. Mirrors with
// no usable pattern or an unparsable URL are dropped.
func resolveMirrors(mirrors []Mirror, servers []Server) []mirror {
	logger := log.WithPrefix("pom")
	var result []mirror
	for _, m := range mirrors {
		var patterns []string
		for p := range strings.SplitSeq(m.MirrorOf, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			patterns = append(patterns, p)
		}
		if len(patterns) == 0 {
			continue
		}

		u, err := url.Parse(m.URL)
		if err != nil {
			// Don't log the wrapped error: url.Error.Error() prints the raw URL,
			// which would leak any userinfo configured in <mirror><url>.
			logger.Debug("Unable to parse mirror url", log.String("id", m.ID))
			continue
		}

		// Maven looks up credentials on the <server> whose id equals the mirror's id,
		// not the original repository's id.
		for _, srv := range servers {
			if srv.ID == m.ID && srv.Username != "" && srv.Password != "" {
				u.User = url.UserPassword(srv.Username, srv.Password)
				break
			}
		}

		logger.Debug("Adding mirror", log.String("id", m.ID), log.String("url", u.Redacted()))
		result = append(result, mirror{
			id:       m.ID,
			patterns: patterns,
			url:      *u,
		})
	}
	return result
}

// matches reports whether this mirror should serve the given repository.
// See https://maven.apache.org/guides/mini/guide-mirror-settings.html
//
// Implements the same order-sensitive semantics as Maven's
// DefaultMirrorSelector.matchPattern in maven-resolver. Patterns are walked
// left-to-right; the loop terminates as soon as either an exact id or an
// exclusion fires. Non-terminal tokens just set the flag and keep iterating
// so that a later "!<id>" can still veto.
//
// Terminal tokens:
//   - "<id>"            — exact match. Returns true.
//   - "!<id>"           — exclusion of an exact id. Returns false.
//
// Non-terminal tokens (set flag, continue):
//   - "*"               — any repository.
//   - "external:*"      — any URL that is not file:// and not localhost /
//     127.0.0.1 / ::1.
//   - "external:http:*" — same as external:*, restricted to the http scheme.
func (m mirror) matches(repoID string, repoURL *url.URL) bool {
	result := false
	for _, p := range m.patterns {
		switch {
		// Exclusion token. A bare "!" without an id is not a valid exclusion,
		// so the length check skips it (matches Maven's repo.length() > 1).
		case len(p) > 1 && p[0] == '!':
			if p[1:] == repoID {
				return false
			}
		case p == repoID:
			return true
		case p == "*":
			result = true
		case p == "external:*":
			if isExternalRepo(repoURL) {
				result = true
			}
		case p == "external:http:*":
			// external:http:* is external:* restricted to the http scheme;
			// https and other schemes must not match.
			if isExternalRepo(repoURL) && repoURL.Scheme == "http" {
				result = true
			}
		}
	}
	return result
}

// isExternalRepo reports whether the URL points to an external repository.
// A repository is considered external when its scheme is not "file" and its
// hostname is not one of the loopback addresses (localhost, 127.0.0.1, ::1).
// A nil URL is treated as non-external so that unparsable URLs never trigger
// an external:* match.
func isExternalRepo(u *url.URL) bool {
	if u == nil || u.Scheme == "file" {
		return false
	}
	h := u.Hostname()
	return h != "localhost" && h != "127.0.0.1" && h != "::1"
}
