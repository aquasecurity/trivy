package doc

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/aquasecurity/go-version/pkg/semver"
	"github.com/aquasecurity/trivy/pkg/version/app"
)

const devVersion = "dev"

// BaseURL returns the base URL for the versioned documentation
func BaseURL(ver string) *url.URL {
	ver = canonicalVersion(ver)
	return &url.URL{
		Scheme: "https",
		Host:   "aquasecurity.github.io",
		Path:   path.Join("trivy", ver),
	}
}

// URL returns the URL for the versioned documentation with the given path
func URL(rawPath, fragment string) string {
	base := BaseURL(app.Version())
	base.Path = path.Join(base.Path, rawPath)
	base.Fragment = fragment
	return base.String()
}

func canonicalVersion(ver string) string {
	if ver == devVersion {
		return ver
	}
	ver = strings.TrimPrefix(ver, "v")
	v, err := semver.Parse(ver)
	if err != nil {
		return devVersion
	}
	// Replace pre-release with "dev"
	// e.g. v0.34.0-beta1+snapshot-1
	if v.IsPreRelease() || v.Metadata() != "" {
		return devVersion
	}
	// Add "v" prefix and cut a patch number, "0.34.0" => "v0.34" for the URL
	return fmt.Sprintf("v%d.%d", v.Major(), v.Minor())
}
