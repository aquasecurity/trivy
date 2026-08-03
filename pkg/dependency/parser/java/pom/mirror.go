package pom

import (
	"cmp"
	"net/url"
	"strings"

	"github.com/samber/lo"

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

// mirrors holds the resolved mirrors from settings.xml and from the config file.
type mirrors struct {
	settings   []mirror             // settings.xml mirrors
	configFile map[string][]url.URL // config-file mirrors; key: mirrorKey(source), value: ordered parsed mirror URL
}

// resolveMirrors resolves and validates both mirror sources into their runtime form:
// it parses every URL — embedding <server> credentials into settings.xml mirrors and
// normalizing config-file keys via mirrorKey — and drops any entry with an unusable
// pattern or an unparsable URL.
func resolveMirrors(settingsMirrors []Mirror, servers []Server, configFileMirrors map[string][]string) mirrors {
	logger := log.WithPrefix("pom")

	var resolved mirrors
	for _, m := range settingsMirrors {
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
		resolved.settings = append(resolved.settings, mirror{
			id:       m.ID,
			patterns: patterns,
			url:      *u,
		})
	}

	for src, targets := range configFileMirrors {
		// Config-file mirror URLs are validated when the config file is parsed (fail-fast).
		srcURL, err := url.Parse(src)
		if err != nil {
			continue
		}

		var mirrorURLs []url.URL
		for _, target := range targets {
			mirrorURL, err := url.Parse(target)
			if err != nil {
				continue
			}
			mirrorURLs = append(mirrorURLs, *mirrorURL)
		}
		if len(mirrorURLs) == 0 {
			continue
		}
		logger.Debug("Added config-file mirror", log.String("source", srcURL.Redacted()),
			log.Any("mirrors", lo.Map(mirrorURLs, func(u url.URL, _ int) string {
				return u.Redacted()
			})))
		if resolved.configFile == nil {
			resolved.configFile = make(map[string][]url.URL)
		}
		resolved.configFile[mirrorKey(*srcURL)] = mirrorURLs
	}

	return resolved
}

// mirrorKey normalizes a repository URL to the key used for config-file mirror lookup.
// The path is cleaned the same way as when an artifact URL is built, so that
// "https://host/maven2/" and "https://host//maven2" resolve to the same key.
//
// The key has to identify the repository, so the parts that don't are dropped as well:
// the credentials that Trivy embeds from a <server> — otherwise a mirrored repository
// with credentials would never match its configured key — and the case of the host,
// which RFC 3986 defines as case-insensitive. The case of the path is kept, as it is
// case-sensitive.
func mirrorKey(u url.URL) string {
	u.User = nil
	u.Host = strings.ToLower(u.Host)
	// JoinPath cleans the path only, leaving any query and fragment alone.
	u.Path = cmp.Or(u.Path, "/")
	return u.JoinPath(".").String()
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
