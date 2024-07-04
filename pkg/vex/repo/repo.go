package repo

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-github/v62/github"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/downloader"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

const (
	SchemaVersion = "0.1"
	manifestFile  = "vex-repository.json"
	indexFile     = "index.json"
)

type Manifest struct {
	Name          string             `json:"name"`
	Description   string             `json:"description"`
	Versions      map[string]Version `json:"versions"`
	LatestVersion string             `json:"latest_version"`
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
	UpdatedAt time.Time               `json:"updated_at"`
	Packages  map[string]PackageEntry `json:"packages"`
}

type PackageEntry struct {
	ID       string `json:"id"`
	Location string `json:"location"`
	Format   string `json:"format"`
}

type rawIndex struct {
	UpdatedAt time.Time      `json:"updated_at"`
	Packages  []PackageEntry `json:"packages"`
}

type Repository struct {
	Name string
	URL  string

	dir string // Root directory for this VEX repository, $CACHE_DIR/vex/repositories/$REPO_NAME/
}

func (r *Repository) Manifest(ctx context.Context) (Manifest, error) {
	filePath := filepath.Join(r.dir, manifestFile)
	log.DebugContext(ctx, "Reading the repository metadata...", log.String("name", r.Name), log.FilePath(filePath))

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
	filePath := filepath.Join(r.dir, indexFile)
	log.DebugContext(ctx, "Reading the repository index...", log.String("name", r.Name), log.FilePath(filePath))

	f, err := os.Open(filePath)
	if err != nil {
		return Index{}, xerrors.Errorf("failed to open the file: %w", err)
	}
	defer f.Close()

	var raw rawIndex
	if err = json.NewDecoder(f).Decode(&raw); err != nil {
		return Index{}, xerrors.Errorf("failed to decode the index: %w", err)
	}

	return Index{
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
		if err = r.githubGet(ctx, u, r.dir); err != nil {
			return xerrors.Errorf("failed to get the repository metadata: %w", err)
		}
		return nil
	}

	u.Path += path.Join(u.Path, ".well-known", manifestFile)
	log.DebugContext(ctx, "Downloading the repository metadata...", log.String("url", u.String()), log.String("dst", r.dir))
	if err := downloader.Download(ctx, u.String(), r.dir, ".", opts.Insecure); err != nil {
		return xerrors.Errorf("failed to download the repository: %w", err)
	}
	return nil
}

func (r *Repository) githubGet(ctx context.Context, u *url.URL, dstDir string) error {
	ss := strings.SplitN(u.Path, "/", 4)
	if len(ss) < 3 {
		return xerrors.Errorf("invalid GitHub URL: %s", u)
	}
	owner := ss[1]
	repo := ss[2]
	filePath := manifestFile
	if len(ss) == 4 {
		filePath = path.Join(ss[3], filePath)
	}

	client := github.NewClient(nil)
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		client = client.WithAuthToken(t)
	}

	log.DebugContext(ctx, "Downloading the repository metadata from GitHub...",
		log.String("owner", owner), log.String("repo", repo), log.String("path", filePath),
		log.String("dst", dstDir))
	rc, _, err := client.Repositories.DownloadContents(ctx, owner, repo, filePath, nil)
	if err != nil {
		return xerrors.Errorf("failed to get the file content: %w", err)
	}
	defer rc.Close()

	f, err := os.Create(filepath.Join(dstDir, manifestFile))
	if err != nil {
		return xerrors.Errorf("failed to create a file: %w", err)
	}
	defer f.Close()

	if _, err = io.Copy(f, rc); err != nil {
		return xerrors.Errorf("failed to copy the file: %w", err)
	}
	return nil
}

func (r *Repository) Update(ctx context.Context, opts Options) error {
	manifest, err := r.Manifest(ctx)
	if err != nil {
		return xerrors.Errorf("failed to get the repository metadata: %w", err)
	}

	majorVersion, _, ok := strings.Cut(SchemaVersion, ".")
	if !ok {
		return xerrors.New("invalid schema version")
	}
	majorVersion = "v" + majorVersion
	ver, ok := manifest.Versions[majorVersion]
	if !ok {
		// TODO: improve error
		return xerrors.Errorf("version %s not found", majorVersion)
	}

	versionDir := filepath.Join(r.dir, majorVersion)
	if !r.needUpdate(ctx, ver, majorVersion) {
		log.InfoContext(ctx, "Need to update repository", log.String("name", r.Name))
		return nil
	}

	log.InfoContext(ctx, "Need to update repository", log.String("name", r.Name))
	log.InfoContext(ctx, "Downloading repository...", log.String("name", r.Name), log.String("url", r.URL))
	if err = r.download(ctx, ver, versionDir, opts); err != nil {
		return xerrors.Errorf("failed to download the repository: %w", err)
	}
	return err
}

func (r *Repository) needUpdate(ctx context.Context, ver Version, versionDir string) bool {
	if !fsutils.DirExists(versionDir) {
		return true
	}

	index, err := r.Index(ctx)
	if err != nil {
		log.DebugContext(ctx, "Failed to get the repository index", log.String("name", r.Name), log.Err(err))
		return true
	}

	now := clock.Clock(ctx).Now()
	if now.After(index.UpdatedAt.Add(ver.UpdateInterval.Duration)) {
		return true
	}

	// TODO: use local metadata.json

	return false
}

func (r *Repository) download(ctx context.Context, ver Version, dst string, opts Options) error {
	if len(ver.Locations) == 0 {
		return xerrors.Errorf("no locations found for version %s", ver.SpecVersion)
	}

	if err := os.MkdirAll(dst, 0700); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}

	var errs error
	for _, loc := range ver.Locations {
		log.DebugContext(ctx, "Downloading repository ...", log.String("url", loc.URL), log.String("dir", dst))
		if err := downloader.Download(ctx, loc.URL, dst, ".", opts.Insecure); err != nil {
			errs = errors.Join(errs, err)
		} else {
			return nil
		}
	}
	return errs
}
