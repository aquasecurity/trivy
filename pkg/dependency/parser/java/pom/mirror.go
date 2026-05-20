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
			logger.Debug("Unable to parse mirror url", log.String("id", m.ID), log.Err(err))
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
//
// patterns originate from <mirrorOf>. Supported tokens:
//   - "*"               — matches any repository
//   - "external:*"      — matches any non-local repository (not file:// and not
//     localhost/127.0.0.1/::1)
//   - "external:http:*" — same as external:* but only for the http scheme
//   - "<id>"            — matches a repository by exact id
//   - "!<id>"           — excludes a repository by id; an exclusion always wins
//     regardless of its position in the list, so "*,!internal"
//     and "!internal,*" behave identically.
//
// See https://maven.apache.org/guides/mini/guide-mirror-settings.html
func (m mirror) matches(repoID string, repoURL *url.URL) bool {
	// First pass: check exclusions. They take priority over any include token in
	// the same list, so we must scan them all before deciding the include result.
	for _, p := range m.patterns {
		if id, ok := strings.CutPrefix(p, "!"); ok && id == repoID {
			return false
		}
	}

	// Second pass: check include tokens.
	for _, p := range m.patterns {
		// Exclusion tokens are already handled in the first pass.
		if strings.HasPrefix(p, "!") {
			continue
		}
		switch p {
		case "*":
			return true
		case "external:*":
			if isExternalRepo(repoURL) {
				return true
			}
		case "external:http:*":
			// external:http:* is external:* restricted to the http scheme;
			// https and other schemes must not match.
			if isExternalRepo(repoURL) && repoURL.Scheme == "http" {
				return true
			}
		default:
			// Any non-keyword token is treated as an exact repository id.
			if p == repoID {
				return true
			}
		}
	}
	return false
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
