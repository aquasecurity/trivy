package github

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/google/go-github/v28/github"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
)

const (
	owner = "aquasecurity"
	repo  = "trivy-db"
)

type RepositoryInterface interface {
	ListReleases(ctx context.Context, opt *github.ListOptions) ([]*github.RepositoryRelease, *github.Response, error)
	DownloadAsset(ctx context.Context, id int64) (io.ReadCloser, string, error)
}

type Repository struct {
	repository *github.RepositoriesService
	git        *github.GitService
	owner      string
	repoName   string
}

func (r Repository) ListReleases(ctx context.Context, opt *github.ListOptions) ([]*github.RepositoryRelease, *github.Response, error) {
	return r.repository.ListReleases(ctx, r.owner, r.repoName, opt)
}

func (r Repository) DownloadAsset(ctx context.Context, id int64) (io.ReadCloser, string, error) {
	return r.repository.DownloadReleaseAsset(ctx, r.owner, r.repoName, id)
}

type Client struct {
	Repository RepositoryInterface
}

func NewClient(ctx context.Context) Client {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	tc := oauth2.NewClient(ctx, ts)
	gc := github.NewClient(tc)

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

func (c Client) DownloadDB(ctx context.Context, fileName string) (io.ReadCloser, error) {
	options := github.ListOptions{}
	releases, _, err := c.Repository.ListReleases(ctx, &options)
	if err != nil {
		return nil, xerrors.Errorf("failed to list releases: %w", err)
	}

	sort.Slice(releases, func(i, j int) bool {
		return releases[i].GetPublishedAt().After(releases[j].GetPublishedAt().Time)
	})

	prefix := fmt.Sprintf("v%d", db.SchemaVersion)
	for _, release := range releases {
		log.Logger.Debugf("release name: %s", release.GetName())
		if !strings.HasPrefix(*release.Name, prefix) {
			continue
		}

		for _, asset := range release.Assets {
			rc, err := c.downloadAsset(ctx, asset, fileName)
			if err != nil {
				log.Logger.Debug(err)
				continue
			}
			return rc, nil
		}

	}
	return nil, xerrors.New("DB file not found")
}

func (c Client) downloadAsset(ctx context.Context, asset github.ReleaseAsset, fileName string) (io.ReadCloser, error) {
	log.Logger.Debugf("asset name: %s", *asset.Name)
	if *asset.Name != fileName {
		return nil, xerrors.New("file name doesn't match")
	}

	rc, url, err := c.Repository.DownloadAsset(ctx, asset.GetID())
	if err != nil {
		return nil, xerrors.Errorf("unable to download the asset: %w", err)
	}

	if rc != nil {
		return rc, nil
	}

	log.Logger.Debugf("asset URL: %s", url)
	resp, err := http.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, xerrors.Errorf("unable to download the asset via URL: %w", err)
	}
	return resp.Body, nil
}
