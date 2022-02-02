package remote

import (
	"context"
	"io/ioutil"
	"net/url"
	"os"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/artifact/local"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
)

type Artifact struct {
	url   string
	local artifact.Artifact
}

func NewArtifact(rawurl string, c cache.ArtifactCache, artifactOpt artifact.Option, scannerOpt config.ScannerOption) (
	artifact.Artifact, func(), error) {
	cleanup := func() {}

	u, err := newURL(rawurl)
	if err != nil {
		return nil, cleanup, err
	}

	tmpDir, err := ioutil.TempDir("", "fanal-remote")
	if err != nil {
		return nil, cleanup, err
	}

	cloneOptions := git.CloneOptions{
		URL:             u.String(),
		Auth:            gitAuth(),
		Progress:        os.Stdout,
		Depth:           1,
		InsecureSkipTLS: artifactOpt.InsecureSkipTLS,
	}

	// suppress clone output if noProgress
	if artifactOpt.NoProgress {
		cloneOptions.Progress = nil
	}

	_, err = git.PlainClone(tmpDir, false, &cloneOptions)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("git error: %w", err)
	}

	cleanup = func() {
		_ = os.RemoveAll(tmpDir)
	}

	art, err := local.NewArtifact(tmpDir, c, artifactOpt, scannerOpt)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("fs artifact: %w", err)
	}

	return Artifact{
		url:   rawurl,
		local: art,
	}, cleanup, nil
}

func (a Artifact) Inspect(ctx context.Context) (types.ArtifactReference, error) {
	ref, err := a.local.Inspect(ctx)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("remote repository error: %w", err)
	}

	ref.Name = a.url
	ref.Type = types.ArtifactRemoteRepository

	return ref, nil
}

func newURL(rawurl string) (*url.URL, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, xerrors.Errorf("url parse error: %w", err)
	}
	// "https://" can be omitted
	// e.g. github.com/aquasecurity/fanal
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
