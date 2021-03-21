package github

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/google/go-github/v33/github"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	owner = "aquasecurity"
	repo  = "trivy-db"
)

// RepositoryInterface defines the operations on repository
type RepositoryInterface interface {
	ListReleases(ctx context.Context, opt *github.ListOptions) ([]*github.RepositoryRelease, *github.Response, error)
	DownloadAsset(ctx context.Context, id int64) (io.ReadCloser, string, error)
}

// Repository implements RepositoryInterface
type Repository struct {
	repository *github.RepositoriesService
	git        *github.GitService
	owner      string
	repoName   string
}

// ListReleases returns all github releases on repository
func (r Repository) ListReleases(ctx context.Context, opt *github.ListOptions) ([]*github.RepositoryRelease, *github.Response, error) {
	return r.repository.ListReleases(ctx, r.owner, r.repoName, opt)
}

// DownloadAsset returns reader object of downloaded object
func (r Repository) DownloadAsset(ctx context.Context, id int64) (io.ReadCloser, string, error) {
	return r.repository.DownloadReleaseAsset(ctx, r.owner, r.repoName, id, nil)
}

// Operation defines the file operations
type Operation interface {
	DownloadDB(ctx context.Context, fileName string) (io.ReadCloser, int, error)
}

// Client implements RepositoryInterface
type Client struct {
	Repository RepositoryInterface
}

// NewClient is the factory method to return Client for RepositoryInterface operations
func NewClient() Client {
	var client *http.Client
	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken != "" {
		log.Logger.Info("Using your github token")
		ctx := context.Background()
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: githubToken})
		client = oauth2.NewClient(ctx, ts)
	}
	gc := github.NewClient(client)

	repo := Repository{
		repository: gc.Repositories,
		git:        gc.Git,
		owner:      owner,
		repoName:   repo,
	}

	return Client{
		Repository: repo,
	}
}

// DownloadDB returns reader object of file content
func (c Client) DownloadDB(ctx context.Context, fileName string) (io.ReadCloser, int, error) {
	options := github.ListOptions{}
	releases, _, err := c.Repository.ListReleases(ctx, &options)
	if err != nil {
		return nil, 0, xerrors.Errorf("failed to list releases: %w", err)
	}

	sort.Slice(releases, func(i, j int) bool {
		return releases[i].GetPublishedAt().After(releases[j].GetPublishedAt().Time)
	})

	prefix := fmt.Sprintf("v%d", db.SchemaVersion)
	for _, release := range releases {
		log.Logger.Debugf("release name: %s", release.GetName())
		if !strings.HasPrefix(release.GetName(), prefix) {
			continue
		}

		for _, asset := range release.Assets {
			rc, size, err := c.downloadAsset(ctx, asset, fileName)
			if err != nil {
				log.Logger.Debug(err)
				continue
			}
			return rc, size, nil
		}

	}
	return nil, 0, xerrors.New("DB file not found")
}

func (c Client) downloadAsset(ctx context.Context, asset *github.ReleaseAsset, fileName string) (io.ReadCloser, int, error) {
	log.Logger.Debugf("asset name: %s", asset.GetName())
	if asset.GetName() != fileName {
		return nil, 0, xerrors.New("file name doesn't match")
	}

	rc, url, err := c.Repository.DownloadAsset(ctx, asset.GetID())
	if err != nil {
		return nil, 0, xerrors.Errorf("unable to download the asset: %w", err)
	}

	if rc != nil {
		return rc, asset.GetSize(), nil
	}

	log.Logger.Debugf("asset URL: %s", url)
	resp, err := http.Get(url) // nolint: gosec
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, 0, xerrors.Errorf("unable to download the asset via URL: %w", err)
	}

	size, err := strconv.Atoi(resp.Header.Get("Content-Length"))
	if err != nil {
		return nil, 0, xerrors.Errorf("invalid size: %w", err)
	}
	return resp.Body, size, nil
}
