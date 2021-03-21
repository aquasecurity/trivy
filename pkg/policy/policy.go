package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/open-policy-agent/opa/bundle"

	"github.com/google/wire"
	"github.com/spf13/afero"
	"k8s.io/utils/clock"

	"github.com/aquasecurity/trivy/pkg/downloader"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils"
)

const bundleURL = "https://knqyf263.github.io/appshield/bundle.tar.gz"

// SuperSet binds the dependencies
var SuperSet = wire.NewSet(
	// clock.Clock
	wire.Struct(new(clock.RealClock)),
	wire.Bind(new(clock.Clock), new(clock.RealClock)),

	// Filesystem
	afero.NewOsFs,

	// policy.Client
	NewClient,
)

type metadata struct {
	Etag          string
	LastUpdatedAt time.Time
}

// Client implements policy operations
type Client struct {
	fs    afero.Fs
	clock clock.Clock
}

// NewClient is the factory method for policy client
func NewClient(fs afero.Fs, clock clock.Clock) Client {
	return Client{
		fs:    fs,
		clock: clock,
	}
}

func (c Client) LoadDefaultPolicies(ctx context.Context) ([]string, error) {
	f, err := os.Open(manifestPath())
	if err != nil {
		return nil, err
	}

	var manifest bundle.Manifest
	if err = json.NewDecoder(f).Decode(&manifest); err != nil {
		return nil, err
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
	f, err := c.fs.Open(metadataPath())
	if err != nil {
		log.Logger.Debug("Failed to open the policy metadata: %s", err)
		return "", true
	}

	var meta metadata
	if err = json.NewDecoder(f).Decode(&meta); err != nil {
		log.Logger.Warn("Policy JSON decode error: %s", err)
		return "", true
	}

	// Update if it's been a day since the last update.
	if c.clock.Now().After(meta.LastUpdatedAt.Add(24 * time.Hour)) {
		return meta.Etag, true
	}

	return "", false

}

func (c Client) DownloadDefaultPolicies(ctx context.Context, etag string) error {
	req, _ := http.NewRequestWithContext(ctx, "HEAD", bundleURL, nil)
	req.Header.Set("If-None-Match", etag)

	client := new(http.Client)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		log.Logger.Info("The default policies has not been updated")
		return nil
	}

	log.Logger.Info("Need to update the default policies")
	log.Logger.Info("Downloading the default policies...")
	dst := contentDir()
	if err = downloader.Download(ctx, bundleURL, dst, dst); err != nil {
		return err
	}

	if err = c.updateMetadata(resp.Header.Get("etag"), c.clock.Now()); err != nil {
		return err
	}

	return nil
}

func (c Client) updateMetadata(etag string, now time.Time) error {
	meta := metadata{
		Etag:          etag,
		LastUpdatedAt: now,
	}

	f, err := c.fs.Create(metadataPath())
	if err != nil {
		return err
	}

	if err = json.NewEncoder(f).Encode(meta); err != nil {
		return err
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
