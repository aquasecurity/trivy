package javadb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/java/jar"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/oci"
)

const (
	SchemaVersion = db.SchemaVersion
	mediaType     = "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip"
)

var (
	// GitHub Container Registry
	DefaultGHCRRepository = fmt.Sprintf("%s:%d", "ghcr.io/aquasecurity/trivy-java-db", SchemaVersion)

	// GCR mirrors
	DefaultGCRRepository = fmt.Sprintf("%s:%d", "mirror.gcr.io/aquasec/trivy-java-db", SchemaVersion)
)

var updater *Updater

type Updater struct {
	repos          []name.Reference
	dbDir          string
	skip           bool
	quiet          bool
	registryOption ftypes.RegistryOptions
	once           sync.Once // we need to update java-db once per run
}

func (u *Updater) Update() error {
	ctx := log.WithContextPrefix(context.Background(), log.PrefixJavaDB)
	metac := db.NewMetadata(u.dbDir)

	meta, err := metac.Get()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return xerrors.Errorf("Java DB metadata error: %w", err)
		} else if u.skip {
			log.ErrorContext(ctx, "The first run cannot skip downloading Java DB")
			return xerrors.New("'--skip-java-db-update' cannot be specified on the first run")
		}
	}

	if (meta.Version != SchemaVersion || !u.isNewDB(ctx, meta)) && !u.skip {
		// Download DB
		// TODO: support remote options
		if err := u.downloadDB(ctx); err != nil {
			return xerrors.Errorf("OCI artifact error: %w", err)
		}

		// Parse the newly downloaded metadata.json
		meta, err = metac.Get()
		if err != nil {
			return xerrors.Errorf("Java DB metadata error: %w", err)
		}

		// Update DownloadedAt
		meta.DownloadedAt = time.Now().UTC()
		if err = metac.Update(meta); err != nil {
			return xerrors.Errorf("Java DB metadata update error: %w", err)
		}
		log.InfoContext(ctx, "Java DB is cached for 3 days. If you want to update the database more frequently, "+
			`"trivy clean --java-db" command clears the DB cache.`)
	}

	return nil
}

func (u *Updater) isNewDB(ctx context.Context, meta db.Metadata) bool {
	now := time.Now().UTC()
	if now.Before(meta.NextUpdate) {
		log.DebugContext(ctx, "Java DB update was skipped because the local Java DB is the latest")
		return true
	}

	if now.Before(meta.DownloadedAt.Add(time.Hour * 24)) { // 1 day
		log.DebugContext(ctx, "Java DB update was skipped because the local Java DB was downloaded during the last day")
		return true
	}
	return false
}

func (u *Updater) downloadDB(ctx context.Context) error {
	log.InfoContext(ctx, "Downloading Java DB...")

	artifacts := oci.NewArtifacts(u.repos, u.registryOption)
	downloadOpt := oci.DownloadOption{
		MediaType: mediaType,
		Quiet:     u.quiet,
	}
	if err := artifacts.Download(ctx, u.dbDir, downloadOpt); err != nil {
		return xerrors.Errorf("failed to download Java DB: %w", err)
	}

	return nil
}

func Init(cacheDir string, javaDBRepositories []name.Reference, skip, quiet bool, registryOption ftypes.RegistryOptions) {
	updater = &Updater{
		repos:          javaDBRepositories,
		dbDir:          dbDir(cacheDir),
		skip:           skip,
		quiet:          quiet,
		registryOption: registryOption,
	}
}

func Update() error {
	if updater == nil {
		return xerrors.New("Java DB client not initialized")
	}

	var err error
	updater.once.Do(func() {
		err = updater.Update()
	})
	return err
}

func Clear(ctx context.Context, cacheDir string) error {
	return os.RemoveAll(dbDir(cacheDir))
}

func dbDir(cacheDir string) string {
	return filepath.Join(cacheDir, "java-db")
}

type DB struct {
	driver db.DB
}

func NewClient() (*DB, error) {
	if err := Update(); err != nil {
		return nil, xerrors.Errorf("Java DB update failed: %s", err)
	}

	dbc, err := db.New(updater.dbDir)
	if err != nil {
		return nil, xerrors.Errorf("Java DB open error: %w", err)
	}

	return &DB{driver: dbc}, nil
}

func (d *DB) Exists(groupID, artifactID string) (bool, error) {
	index, err := d.driver.SelectIndexByArtifactIDAndGroupID(artifactID, groupID)
	if err != nil {
		return false, err
	}
	return index.ArtifactID != "", nil
}

func (d *DB) SearchBySHA1(sha1 string) (jar.Properties, error) {
	index, err := d.driver.SelectIndexBySha1(sha1)
	if err != nil {
		return jar.Properties{}, xerrors.Errorf("select error: %w", err)
	} else if index.ArtifactID == "" {
		return jar.Properties{}, xerrors.Errorf("digest %s: %w", sha1, jar.ArtifactNotFoundErr)
	}
	return jar.Properties{
		GroupID:    index.GroupID,
		ArtifactID: index.ArtifactID,
		Version:    index.Version,
	}, nil
}

func (d *DB) SearchByArtifactID(artifactID, version string) (string, error) {
	indexes, err := d.driver.SelectIndexesByArtifactIDAndFileType(artifactID, version, types.JarType)
	if err != nil {
		return "", xerrors.Errorf("select error: %w", err)
	} else if len(indexes) == 0 {
		return "", xerrors.Errorf("artifactID %s: %w", artifactID, jar.ArtifactNotFoundErr)
	}
	sort.Slice(indexes, func(i, j int) bool {
		return indexes[i].GroupID < indexes[j].GroupID
	})

	// Some artifacts might have the same artifactId.
	// e.g. "javax.servlet:jstl" and "jstl:jstl"
	groupIDs := make(map[string]int)
	for _, index := range indexes {
		if i, ok := groupIDs[index.GroupID]; ok {
			groupIDs[index.GroupID] = i + 1
			continue
		}
		groupIDs[index.GroupID] = 1
	}
	maxCount := 0
	var groupID string
	for k, v := range groupIDs {
		if v > maxCount {
			maxCount = v
			groupID = k
		}
	}

	return groupID, nil
}

func (d *DB) Close() error {
	if d == nil {
		return nil
	}
	return d.driver.Close()
}
