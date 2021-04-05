package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/open-policy-agent/opa/bundle"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	"github.com/aquasecurity/trivy/pkg/downloader"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils"
)

// TODO: fix
const bundleURL = "https://knqyf263.github.io/appshield/bundle.tar.gz"

type options struct {
	url   string
	clock clock.Clock
}

type option func(*options)

func WithBundleURL(url string) option {
	return func(opts *options) {
		opts.url = url
	}
}

func WithClock(clock clock.Clock) option {
	return func(opts *options) {
		opts.clock = clock
	}
}

type Metadata struct {
	Etag          string
	LastUpdatedAt time.Time
}

// Client implements policy operations
type Client struct {
	opts options
}

// NewClient is the factory method for policy client
func NewClient(opts ...option) Client {
	o := &options{
		url:   bundleURL,
		clock: clock.RealClock{},
	}

	for _, opt := range opts {
		opt(o)
	}
	return Client{
		opts: *o,
	}
}

func (c Client) LoadDefaultPolicies() ([]string, error) {
	f, err := os.Open(manifestPath())
	if err != nil {
		return nil, xerrors.Errorf("manifest file open error (%s): %w", manifestPath(), err)
	}

	var manifest bundle.Manifest
	if err = json.NewDecoder(f).Decode(&manifest); err != nil {
		return nil, xerrors.Errorf("json decode error (%s): %w", manifestPath(), err)
	}

	if manifest.Roots == nil || len(*manifest.Roots) == 0 {
		return []string{contentDir()}, nil
	}

	var policyPaths []string
	for _, root := range *manifest.Roots {
		policyPaths = append(policyPaths, filepath.Join(contentDir(), root))
	}

	return policyPaths, nil
}

func (c Client) NeedsUpdate() (string, bool) {
	f, err := os.Open(metadataPath())
	if err != nil {
		log.Logger.Debugf("Failed to open the policy metadata: %s", err)
		return "", true
	}

	var meta Metadata
	if err = json.NewDecoder(f).Decode(&meta); err != nil {
		log.Logger.Warnf("Policy JSON decode error: %s", err)
		return "", true
	}

	// Update if it's been a day since the last update.
	if c.opts.clock.Now().After(meta.LastUpdatedAt.Add(24 * time.Hour)) {
		return meta.Etag, true
	}

	return "", false

}

func (c Client) DownloadDefaultPolicies(ctx context.Context, etag string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.opts.url, nil)
	if err != nil {
		return xerrors.Errorf("http client error: %w", err)
	}
	req.Header.Set("If-None-Match", etag)

	client := new(http.Client)
	resp, err := client.Do(req)
	if err != nil {
		return xerrors.Errorf("http request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		log.Logger.Info("The default policies has not been updated")
		return nil
	}

	log.Logger.Info("Need to update the default policies")
	log.Logger.Info("Downloading the default policies...")
	dst := contentDir()
	if err = downloader.Download(ctx, c.opts.url, dst, dst); err != nil {
		return xerrors.Errorf("policy download error: %w", err)
	}

	if err = c.updateMetadata(resp.Header.Get("etag"), c.opts.clock.Now()); err != nil {
		return xerrors.Errorf("unable to update the policy metadata: %w", err)
	}

	return nil
}

func (c Client) updateMetadata(etag string, now time.Time) error {
	meta := Metadata{
		Etag:          etag,
		LastUpdatedAt: now,
	}

	f, err := os.Create(metadataPath())
	if err != nil {
		return xerrors.Errorf("failed to open a policy manifest: %w", err)
	}

	if err = json.NewEncoder(f).Encode(meta); err != nil {
		return xerrors.Errorf("json encode error: %w", err)
	}

	return nil
}

func policyDir() string {
	return filepath.Join(utils.CacheDir(), "policy")
}

func contentDir() string {
	return filepath.Join(policyDir(), "content")
}

func metadataPath() string {
	return filepath.Join(policyDir(), "metadata.json")
}

func manifestPath() string {
	return filepath.Join(contentDir(), bundle.ManifestExt)
}
