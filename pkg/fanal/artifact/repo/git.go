package repo

import (
	"cmp"
	"net/url"
	"os"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/hashicorp/go-multierror"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/local"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	xos "github.com/aquasecurity/trivy/pkg/x/os"
)

var _ Walker = (*walker.FS)(nil)

type Walker interface {
	Walk(root string, opt walker.Option, fn walker.WalkFunc) error
}

func NewArtifact(target string, c cache.ArtifactCache, w Walker, artifactOpt artifact.Option) (artifact.Artifact, func(), error) {
	var cleanup func()
	var errs error

	artifactOpt.Type = types.TypeRepository

	// Try the local repository
	art, err := tryLocalRepo(target, c, w, artifactOpt)
	if err == nil {
		return art, func() {}, nil
	}
	errs = multierror.Append(errs, err)

	// Try the remote git repository
	art, cleanup, err = tryRemoteRepo(target, c, w, artifactOpt)
	if err == nil {
		return art, cleanup, nil
	}
	errs = multierror.Append(errs, err)

	// Return errors
	return nil, cleanup, errs
}

func tryLocalRepo(target string, c cache.ArtifactCache, w Walker, artifactOpt artifact.Option) (artifact.Artifact, error) {
	if _, err := os.Stat(target); err != nil {
		return nil, xerrors.Errorf("no such path: %w", err)
	}

	art, err := local.NewArtifact(target, c, w, artifactOpt)
	if err != nil {
		return nil, xerrors.Errorf("local repo artifact error: %w", err)
	}
	return art, nil
}

func tryRemoteRepo(target string, c cache.ArtifactCache, w Walker, artifactOpt artifact.Option) (artifact.Artifact, func(), error) {
	cleanup := func() {}
	u, err := newURL(target)
	if err != nil {
		return nil, cleanup, err
	}

	tmpDir, err := cloneRepo(u, artifactOpt)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("repository clone error: %w", err)
	}

	cleanup = func() { _ = os.RemoveAll(tmpDir) }

	artifactOpt.Original = target
	if u.User != nil {
		// Keep credentials out of the artifact name and logs.
		redacted := *u
		redacted.User = nil
		artifactOpt.Original = redacted.String()
	}
	art, err := local.NewArtifact(tmpDir, c, w, artifactOpt)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("fs artifact: %w", err)
	}

	return art, cleanup, nil

}

func cloneRepo(u *url.URL, artifactOpt artifact.Option) (string, error) {
	tmpDir, err := xos.MkdirTemp("", "git-clone-")
	if err != nil {
		return "", xerrors.Errorf("failed to create a temp dir: %w", err)
	}

	cloneOptions := git.CloneOptions{
		URL:             u.String(),
		Auth:            gitAuth(u.Hostname()),
		Progress:        os.Stderr,
		InsecureSkipTLS: artifactOpt.Insecure,
	}

	// suppress clone output if noProgress
	if artifactOpt.NoProgress {
		cloneOptions.Progress = nil
	}

	if artifactOpt.RepoCommit == "" {
		cloneOptions.Depth = 1
	}

	if artifactOpt.RepoBranch != "" {
		cloneOptions.ReferenceName = plumbing.NewBranchReferenceName(artifactOpt.RepoBranch)
		cloneOptions.SingleBranch = true
	}

	if artifactOpt.RepoTag != "" {
		cloneOptions.ReferenceName = plumbing.NewTagReferenceName(artifactOpt.RepoTag)
		cloneOptions.SingleBranch = true
	}

	r, err := git.PlainClone(tmpDir, false, &cloneOptions)
	if err != nil {
		return "", xerrors.Errorf("git clone error: %w", err)
	}

	if artifactOpt.RepoCommit != "" {
		w, err := r.Worktree()
		if err != nil {
			return "", xerrors.Errorf("git worktree error: %w", err)
		}

		err = w.Checkout(&git.CheckoutOptions{
			Hash: plumbing.NewHash(artifactOpt.RepoCommit),
		})
		if err != nil {
			return "", xerrors.Errorf("git checkout error: %w", err)
		}
	}

	return tmpDir, nil
}

func newURL(rawurl string) (*url.URL, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, xerrors.Errorf("url parse error: %w", err)
	}
	// "https://" can be omitted
	// e.g. github.com/aquasecurity/trivy
	if u.Scheme == "" {
		u.Scheme = "https"
	}

	return u, nil
}

// defaultGitUsername can be any non-empty username for HTTPS Git operations
// against GitHub and GitLab.
const defaultGitUsername = "fanal-aquasecurity-scan"

// defaultBitbucketUsername is the username Bitbucket expects when
// authenticating with a repository access token over HTTPS.
const defaultBitbucketUsername = "x-token-auth"

// tokenForHost returns the credentials to use for the given repository host.
// The token is selected based on the hosting platform so that, e.g., a
// BITBUCKET_TOKEN is used for bitbucket.org repositories even when
// GITHUB_TOKEN/GITLAB_TOKEN are also set (see issue #6833).
//
// For unknown hosts (self-hosted instances, local test servers, ...), the
// tokens are tried in the order GITHUB_TOKEN, GITLAB_TOKEN, BITBUCKET_TOKEN
// to preserve the historical behavior.
func tokenForHost(host string) (username, token string) {
	username, token = selectTokenForHost(host)
	if token == "" {
		// No usable token: report no credentials at all.
		return "", ""
	}
	return username, token
}

func selectTokenForHost(host string) (username, token string) {
	host = strings.ToLower(strings.TrimSpace(host))

	switch {
	case host == "github.com" || strings.HasSuffix(host, ".github.com"):
		return defaultGitUsername, os.Getenv("GITHUB_TOKEN")
	case host == "gitlab.com" || strings.HasSuffix(host, ".gitlab.com") || strings.Contains(host, "gitlab"):
		return defaultGitUsername, os.Getenv("GITLAB_TOKEN")
	case host == "bitbucket.org" || strings.HasSuffix(host, ".bitbucket.org") || strings.Contains(host, "bitbucket"):
		// Bitbucket app passwords require the account username, while
		// repository/workspace access tokens use "x-token-auth".
		// BITBUCKET_USERNAME allows overriding the default.
		return cmp.Or(os.Getenv("BITBUCKET_USERNAME"), defaultBitbucketUsername), os.Getenv("BITBUCKET_TOKEN")
	}

	// Unknown host: fall back to the historical precedence order.
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		return defaultGitUsername, token
	}
	if token := os.Getenv("GITLAB_TOKEN"); token != "" {
		return defaultGitUsername, token
	}
	if token := os.Getenv("BITBUCKET_TOKEN"); token != "" {
		return cmp.Or(os.Getenv("BITBUCKET_USERNAME"), defaultBitbucketUsername), token
	}
	return "", ""
}

// Helper function to pick the token matching the repository host from env
// vars in order to make authenticated requests to access private repos.
// Returns nil when no token is available, making the request unauthenticated.
func gitAuth(host string) http.AuthMethod {
	username, token := tokenForHost(host)
	if token == "" {
		// If no token was provided, we simply return a nil,
		// which will make the request to be unauthenticated
		return nil
	}
	return &http.BasicAuth{
		Username: username,
		Password: token,
	}
}
