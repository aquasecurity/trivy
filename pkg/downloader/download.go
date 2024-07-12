package downloader

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/go-github/v62/github"
	getter "github.com/hashicorp/go-getter"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

var ErrSkipDownload = errors.New("skip download")

type Options struct {
	Insecure bool
	Auth     Auth
	ETag     string
}

type Auth struct {
	Username string
	Password string
	Token    string
}

// DownloadToTempDir downloads the configured source to a temp dir.
func DownloadToTempDir(ctx context.Context, url string, opts Options) (string, error) {
	tempDir, err := os.MkdirTemp("", "trivy-download")
	if err != nil {
		return "", xerrors.Errorf("failed to create a temp dir: %w", err)
	}

	pwd, err := os.Getwd()
	if err != nil {
		return "", xerrors.Errorf("unable to get the current dir: %w", err)
	}

	if _, err = Download(ctx, url, tempDir, pwd, opts); err != nil {
		return "", xerrors.Errorf("download error: %w", err)
	}

	return tempDir, nil
}

// Download downloads the configured source to the destination.
func Download(ctx context.Context, src, dst, pwd string, opts Options) (string, error) {
	// go-getter doesn't allow the dst directory already exists if the src is directory.
	if fsutils.DirExists(src) {
		_ = os.RemoveAll(dst)
	}

	var clientOpts []getter.ClientOption
	if opts.Insecure {
		clientOpts = append(clientOpts, getter.WithInsecure())
	}

	// Clone the global map so that it will not be accessed concurrently.
	getters := maps.Clone(getter.Getters)

	// Overwrite the file getter so that a file will be copied
	getters["file"] = &getter.FileGetter{Copy: true}

	// Since "httpGetter" is a global pointer and the state is shared,
	// once it is executed without "WithInsecure()",
	// it cannot enable WithInsecure() afterwards because its state is preserved.
	// Therefore, we need to create a new "HttpGetter" instance every time.
	// cf. https://github.com/hashicorp/go-getter/blob/5a63fd9c0d5b8da8a6805e8c283f46f0dacb30b3/get.go#L63-L65
	transport := NewCustomTransport(opts.Auth, opts.ETag)
	httpGetter := &getter.HttpGetter{
		Netrc: true,
		Client: &http.Client{
			Transport: transport,
			Timeout:   time.Minute * 5,
		},
	}
	getters["http"] = httpGetter
	getters["https"] = httpGetter

	// Build the client
	client := &getter.Client{
		Ctx:     ctx,
		Src:     src,
		Dst:     dst,
		Pwd:     pwd,
		Getters: getters,
		Mode:    getter.ClientModeAny,
		Options: clientOpts,
	}

	if err := client.Get(); err != nil {
		return "", xerrors.Errorf("failed to download: %w", err)
	}

	return transport.newETag, nil
}

type CustomTransport struct {
	auth       Auth
	cachedETag string
	newETag    string
}

func NewCustomTransport(auth Auth, etag string) *CustomTransport {
	return &CustomTransport{
		auth:       auth,
		cachedETag: etag,
	}
}

func (t *CustomTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.cachedETag != "" {
		req.Header.Set("If-None-Match", t.cachedETag)
	}
	if t.auth.Token != "" {
		req.Header.Set("Authorization", "Bearer "+t.auth.Token)
	} else if t.auth.Username != "" || t.auth.Password != "" {
		req.SetBasicAuth(t.auth.Username, t.auth.Password)
	}

	var transport http.RoundTripper
	if req.URL.Host == "github.com" {
		transport = NewGitHubTransport(req.URL, t.auth.Token)
	}
	if transport == nil {
		transport = http.DefaultTransport
	}

	res, err := transport.RoundTrip(req)
	if err != nil {
		return nil, xerrors.Errorf("failed to round trip: %w", err)
	}

	switch res.StatusCode {
	case http.StatusOK, http.StatusPartialContent:
		// Update the ETag
		t.newETag = res.Header.Get("ETag")
	case http.StatusNotModified:
		return nil, ErrSkipDownload
	}

	return res, nil
}

func NewGitHubTransport(u *url.URL, token string) http.RoundTripper {
	client := newGitHubClient(token)
	ss := strings.SplitN(u.Path, "/", 4)
	if len(ss) < 4 || strings.HasPrefix(ss[3], "archive/") {
		// Use the default transport from go-github for authentication
		return client.Client().Transport
	}

	return &GitHubContentTransport{
		owner:    ss[1],
		repo:     ss[2],
		filePath: ss[3],
		client:   client,
	}
}

// GitHubContentTransport is a round tripper for downloading the GitHub content.
type GitHubContentTransport struct {
	owner    string
	repo     string
	filePath string
	client   *github.Client
}

// RoundTrip calls the GitHub API to download the content.
func (t *GitHubContentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	_, res, err := t.client.Repositories.DownloadContents(req.Context(), t.owner, t.repo, t.filePath, nil)
	if err != nil {
		return nil, xerrors.Errorf("failed to get the file content: %w", err)
	}
	return res.Response, nil
}

func newGitHubClient(token string) *github.Client {
	client := github.NewClient(nil)
	token = cmp.Or(token, os.Getenv("GITHUB_TOKEN"))
	if token != "" {
		client = client.WithAuthToken(token)
	}
	return client
}
