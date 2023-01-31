package javadb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/java/jar"
	"github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/aquasecurity/trivy-java-db/pkg/metadata"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/oci"
)

const (
	version                 = 1
	defaultJavaDBRepository = "ghcr.io/aquasecurity/trivy-java-db"
	mediaType               = "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip"
)

var (
	updater Updater
	client  DB
)

type Updater struct {
	repo     string
	dbDir    string
	skip     bool
	quiet    bool
	insecure bool

	once sync.Once
	err  error
}

func (u *Updater) Update() error {
	u.once.Do(func() {
		dbDir := u.dbDir
		metac := metadata.New(dbDir)

		var meta metadata.Metadata
		meta, u.err = metac.Get()
		if u.err != nil {
			if !errors.Is(u.err, os.ErrNotExist) {
				return
			} else if u.skip {
				log.Logger.Error("The first run cannot skip downloading java DB")
				u.err = xerrors.New("--skip-java-update cannot be specified on the first run")
				return
			}
		}

		if (meta.Version != version || meta.NextUpdate.Before(time.Now().UTC())) && !u.skip {
			// Download DB
			log.Logger.Info("Downloading the Java DB...")

			var a *oci.Artifact
			if a, u.err = oci.NewArtifact(u.repo, mediaType, u.quiet, u.insecure); u.err != nil {
				return
			}
			if u.err = a.Download(context.Background(), dbDir); u.err != nil {
				return
			}

			// Parse the newly downloaded metadata.json
			meta, u.err = metac.Get()
			if u.err != nil {
				return
			}

			// Update DownloadedAt
			meta.DownloadedAt = time.Now().UTC()
			if u.err = metac.Update(meta); u.err != nil {
				return
			}
		}

		var dbc db.DB
		if dbc, u.err = db.New(dbDir); u.err != nil {
			return
		}
		client = DB{
			driver: dbc,
		}
	})
	if u.err != nil {
		return xerrors.Errorf("Java DB update error: %w", u.err)
	}
	return nil
}

func Init(cacheDir string, skip, quiet, insecure bool) {
	updater = Updater{
		repo:     fmt.Sprintf("%s:%d", defaultJavaDBRepository, version), // TODO: make it configurable
		dbDir:    filepath.Join(cacheDir, "java-db"),
		skip:     skip,
		quiet:    quiet,
		insecure: insecure,
	}
}

type DB struct {
	driver db.DB
}

func Client() (*DB, error) {
	// Not return the same error multiple times
	if updater.err != nil {
		return nil, nil
	} else if err := updater.Update(); err != nil {
		return nil, xerrors.Errorf("Java DB update failed: %s", err)
	}
	return &client, nil
}

func (d *DB) Exists(groupID, artifactID string) (bool, error) {
	index, err := d.driver.SelectIndexByArtifactIDAndGroupID(groupID, artifactID)
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

func (d *DB) SearchByArtifactID(artifactID string) (string, error) {
	indexes, err := d.driver.SelectIndexesByArtifactIDAndFileType(artifactID, types.JarType)
	if err != nil {
		return "", xerrors.Errorf("select error: %w", err)
	} else if len(indexes) == 0 {
		return "", xerrors.Errorf("artifactID %s: %w", artifactID, jar.ArtifactNotFoundErr)
	}

	// Some artifacts might have the same artifactId.
	// e.g. "javax.servlet:jstl" and "jstl:jstl"
	groupIDs := map[string]int{}
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
			groupID = k
		}
	}

	return groupID, nil
}
