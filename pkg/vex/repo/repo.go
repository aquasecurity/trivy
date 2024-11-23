package repo

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-getter"
	"github.com/hashicorp/go-multierror"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/downloader"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

const (
	SchemaVersion = "0.1"

	manifestFile      = "vex-repository.json"
	indexFile         = "index.json"
	cacheMetadataFile = "cache.json"
)

type Manifest struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Versions    []Version `json:"versions"`
}

type Version struct {
	SpecVersion    string     `json:"spec_version"`
	Locations      []Location `json:"locations"`
	UpdateInterval Duration   `json:"update_interval"`
}

// Duration is a wrapper around time.Duration that implements UnmarshalJSON
type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return xerrors.Errorf("duration unmarshal error: %w", err)
	}

	var err error
	d.Duration, err = time.ParseDuration(s)
	if err != nil {
		return xerrors.Errorf("duration parse error: %w", err)
	}
	return nil
}

type Location struct {
	URL string `json:"url"`
}

type Index struct {
	Path      string // Path to the index file
	UpdatedAt time.Time
	Packages  map[string]PackageEntry
}

type PackageEntry struct {
	ID       string `json:"id"`
	Location string `json:"location"`
	Format   string `json:"format"`
}

type RawIndex struct {
	UpdatedAt time.Time      `json:"updated_at"`
	Packages  []PackageEntry `json:"packages"`
}

type Repository struct {
	Name     string
	URL      string
	Enabled  bool
	Username string
	Password string
	Token    string // For Bearer

	dir string // Root directory for this VEX repository, $CACHE_DIR/vex/repositories/$REPO_NAME/
}

type CacheMetadata struct {
	UpdatedAt time.Time         // Last updated time
	ETags     map[string]string // Last ETag for each URL
}

func (r *Repository) Manifest(ctx context.Context, opts Options) (Manifest, error) {
	filePath := filepath.Join(r.dir, manifestFile)
	if !fsutils.FileExists(filePath) {
		if err := r.downloadManifest(ctx, opts); err != nil {
			return Manifest{}, xerrors.Errorf("failed to download the repository metadata: %w", err)
		}
	}

	log.DebugContext(ctx, "Reading the repository metadata...", log.String("repo", r.Name), log.FilePath(filePath))
	f, err := os.Open(filePath)
	if err != nil {
		return Manifest{}, xerrors.Errorf("failed to open the file: %w", err)
	}
	defer f.Close()

	var manifest Manifest
	if err = json.NewDecoder(f).Decode(&manifest); err != nil {
		return Manifest{}, xerrors.Errorf("failed to decode the metadata: %w", err)
	}
	return manifest, nil
}

func (r *Repository) Index(ctx context.Context) (Index, error) {
	filePath := filepath.Join(r.dir, SchemaVersion, indexFile)
	log.DebugContext(ctx, "Reading the repository index...", log.String("repo", r.Name), log.FilePath(filePath))

	f, err := os.Open(filePath)
	if err != nil {
		return Index{}, xerrors.Errorf("failed to open the file: %w", err)
	}
	defer f.Close()

	var raw RawIndex
	if err = json.NewDecoder(f).Decode(&raw); err != nil {
		return Index{}, xerrors.Errorf("failed to decode the index: %w", err)
	}

	return Index{
		Path:      filePath,
		UpdatedAt: raw.UpdatedAt,
		Packages:  lo.KeyBy(raw.Packages, func(p PackageEntry) string { return p.ID }),
	}, nil
}

func (r *Repository) downloadManifest(ctx context.Context, opts Options) error {
	if err := os.MkdirAll(r.dir, 0700); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}

	u, err := url.Parse(r.URL)
	if err != nil {
		return xerrors.Errorf("failed to parse the URL: %w", err)
	}

	if u.Host == "github.com" {
		u.Path = path.Join(u.Path, manifestFile)
	} else {
		u.Path = path.Join(u.Path, ".well-known", manifestFile)
	}

	log.DebugContext(ctx, "Downloading the repository metadata...", log.String("url", u.String()), log.String("dst", r.dir))
	_, err = downloader.Download(ctx, u.String(), filepath.Join(r.dir, manifestFile), ".", downloader.Options{
		Insecure: opts.Insecure,
		Auth: downloader.Auth{
			Username: r.Username,
			Password: r.Password,
			Token:    r.Token,
		},
		ClientMode: getter.ClientModeFile,
	})
	if err != nil {
		_ = os.RemoveAll(r.dir)
		return xerrors.Errorf("failed to download the repository: %w", err)
	}
	return nil
}

func (r *Repository) Update(ctx context.Context, opts Options) error {
	manifest, err := r.Manifest(ctx, opts)
	if err != nil {
		return xerrors.Errorf("failed to get the repository metadata: %w", err)
	}

	ver, err := r.selectSupportedVersion(manifest.Versions)
	if err != nil {
		return xerrors.Errorf("version %s not found", SchemaVersion)
	}

	versionDir := filepath.Join(r.dir, SchemaVersion)
	if !r.needUpdate(ctx, ver, versionDir) {
		log.InfoContext(ctx, "No need to check repository updates", log.String("repo", r.Name))
		return nil
	}

	log.InfoContext(ctx, "Updating repository...", log.String("repo", r.Name), log.String("url", r.URL))
	if err = r.download(ctx, ver, versionDir, opts); err != nil {
		return xerrors.Errorf("failed to download the repository: %w", err)
	}
	return err
}

func (r *Repository) needUpdate(ctx context.Context, ver Version, versionDir string) bool {
	if !fsutils.DirExists(versionDir) {
		return true
	}

	m, err := r.cacheMetadata()
	if err != nil {
		log.DebugContext(ctx, "Failed to get repository cache metadata", log.String("repo", r.Name), log.Err(err))
		return true
	}

	now := clock.Clock(ctx).Now()
	log.DebugContext(ctx, "Checking if the repository needs to be updated...", log.String("repo", r.Name),
		log.Time("last_update", m.UpdatedAt), log.Duration("update_interval", ver.UpdateInterval.Duration))
	if now.After(m.UpdatedAt.Add(ver.UpdateInterval.Duration)) {
		return true
	}
	return false
}

func (r *Repository) download(ctx context.Context, ver Version, dst string, opts Options) error {
	if len(ver.Locations) == 0 {
		return xerrors.Errorf("no locations found for version %s", ver.SpecVersion)
	}
	if err := os.MkdirAll(dst, 0700); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}

	m, err := r.cacheMetadata()
	if err != nil {
		return xerrors.Errorf("failed to get the repository cache metadata: %w", err)
	}
	etags := lo.Ternary(m.ETags == nil, make(map[string]string), m.ETags)

	var errs error
	for _, loc := range ver.Locations {
		logger := log.With(log.String("repo", r.Name))
		logger.DebugContext(ctx, "Downloading repository to cache dir...", log.String("url", loc.URL),
			log.String("dir", dst), log.String("etag", etags[loc.URL]))
		etag, err := downloader.Download(ctx, loc.URL, dst, ".", downloader.Options{
			Insecure: opts.Insecure,
			Auth: downloader.Auth{
				Username: r.Username,
				Password: r.Password,
				Token:    r.Token,
			},
			ETag: etags[loc.URL],
		})
		switch {
		case errors.Is(err, downloader.ErrSkipDownload):
			logger.DebugContext(ctx, "No updates in the repository", log.String("url", r.URL))
			etag = etags[loc.URL] // Keep the old ETag
			// Update last updated time so that Trivy will not try to download the same URL soon
		case err != nil:
			errs = multierror.Append(errs, err)
			continue // Try the next location
		default:
			// Successfully downloaded
		}

		// Update the cache metadata
		etags[loc.URL] = etag
		now := clock.Clock(ctx).Now()
		if err = r.updateCacheMetadata(ctx, CacheMetadata{
			UpdatedAt: now,
			ETags:     etags,
		}); err != nil {
			return xerrors.Errorf("failed to update the repository cache metadata: %w", err)
		}
		logger.DebugContext(ctx, "Updated repository cache metadata", log.String("etag", etag),
			log.Time("updated_at", now))
		return nil
	}
	if errs != nil {
		return xerrors.Errorf("failed to download the repository: %w", errs)
	}
	return nil
}

func (r *Repository) cacheMetadata() (CacheMetadata, error) {
	filePath := filepath.Join(r.dir, cacheMetadataFile)
	if !fsutils.FileExists(filePath) {
		return CacheMetadata{}, nil
	}
	f, err := os.Open(filePath)
	if err != nil {
		return CacheMetadata{}, xerrors.Errorf("failed to open the file: %w", err)
	}
	defer f.Close()

	var metadata CacheMetadata
	if err = json.NewDecoder(f).Decode(&metadata); err != nil {
		return CacheMetadata{}, xerrors.Errorf("failed to decode the cache metadata: %w", err)
	}
	return metadata, nil
}

func (r *Repository) selectSupportedVersion(versions []Version) (Version, error) {
	for _, ver := range versions {
		// Versions should exactly match until the spec version reaches 1.0.
		// After reaching 1.0, we can select the latest version that has the same major version.
		if ver.SpecVersion == SchemaVersion {
			return ver, nil
		}
	}
	return Version{}, xerrors.New("no supported version found")
}

func (r *Repository) updateCacheMetadata(ctx context.Context, metadata CacheMetadata) error {
	filePath := filepath.Join(r.dir, cacheMetadataFile)
	log.DebugContext(ctx, "Updating repository cache metadata...", log.FilePath(filePath))

	f, err := os.Create(filePath)
	if err != nil {
		return xerrors.Errorf("failed to create the file: %w", err)
	}
	defer f.Close()

	if err = json.NewEncoder(f).Encode(metadata); err != nil {
		return xerrors.Errorf("failed to encode the metadata: %w", err)
	}
	return nil
}
