package repo

import (
	"context"
	"net/url"
	"os"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/hashicorp/go-multierror"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/local"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type Artifact struct {
	url   string
	local artifact.Artifact
}

func NewArtifact(target string, c cache.ArtifactCache, artifactOpt artifact.Option) (
	artifact.Artifact, func(), error) {

	var cleanup func()
	var errs error

	// Try the local repository
	art, err := tryLocalRepo(target, c, artifactOpt)
	if err == nil {
		return art, func() {}, nil
	}
	errs = multierror.Append(errs, err)

	// Try the remote git repository
	art, cleanup, err = tryRemoteRepo(target, c, artifactOpt)
	if err == nil {
		return art, cleanup, nil
	}
	errs = multierror.Append(errs, err)

	// Return errors
	return nil, cleanup, errs
}

func (a Artifact) Inspect(ctx context.Context) (types.ArtifactReference, error) {
	ref, err := a.local.Inspect(ctx)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("remote repository error: %w", err)
	}

	if a.url != "" {
		ref.Name = a.url
	}
	ref.Type = types.ArtifactRepository

	return ref, nil
}

func (Artifact) Clean(_ types.ArtifactReference) error {
	return nil
}

func tryLocalRepo(target string, c cache.ArtifactCache, artifactOpt artifact.Option) (artifact.Artifact, error) {
	if _, err := os.Stat(target); err != nil {
		return nil, xerrors.Errorf("no such path: %w", err)
	}

	art, err := local.NewArtifact(target, c, artifactOpt)
	if err != nil {
		return nil, xerrors.Errorf("local repo artifact error: %w", err)
	}
	return Artifact{
		local: art,
	}, nil
}

func tryRemoteRepo(target string, c cache.ArtifactCache, artifactOpt artifact.Option) (artifact.Artifact, func(), error) {
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

	art, err := local.NewArtifact(tmpDir, c, artifactOpt)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("fs artifact: %w", err)
	}

	return Artifact{
		url:   target,
		local: art,
	}, cleanup, nil

}

func cloneRepo(u *url.URL, artifactOpt artifact.Option) (string, error) {
	tmpDir, err := os.MkdirTemp("", "trivy-remote-repo")
	if err != nil {
		return "", xerrors.Errorf("failed to create a temp dir: %w", err)
	}

	cloneOptions := git.CloneOptions{
		URL:             u.String(),
		Auth:            gitAuth(),
		Progress:        os.Stdout,
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

// Helper function to check for a GitHub/GitLab token from env vars in order to
// make authenticated requests to access private repos
func gitAuth() *http.BasicAuth {
	var auth *http.BasicAuth

	// The username can be anything for HTTPS Git operations
	gitUsername := "fanal-aquasecurity-scan"

	// We first check if a GitHub token was provided
	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken != "" {
		auth = &http.BasicAuth{
			Username: gitUsername,
			Password: githubToken,
		}
		return auth
	}

	// Otherwise we check if a GitLab token was provided
	gitlabToken := os.Getenv("GITLAB_TOKEN")
	if gitlabToken != "" {
		auth = &http.BasicAuth{
			Username: gitUsername,
			Password: gitlabToken,
		}
		return auth
	}

	// If no token was provided, we simply return a nil,
	// which will make the request to be unauthenticated
	return nil

}
