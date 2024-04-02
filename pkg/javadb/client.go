package javadb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/xerrors"

	"github.com/deepfactor-io/go-dep-parser/pkg/java/jar"
	"github.com/deepfactor-io/javadb/pkg/db"
	"github.com/deepfactor-io/javadb/pkg/types"
	ftypes "github.com/deepfactor-io/trivy/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/pkg/log"
	"github.com/deepfactor-io/trivy/pkg/oci"
)

const (
	mediaType = "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip"
)

var updater *Updater

type Updater struct {
	repo           string
	dbDir          string
	skip           bool
	quiet          bool
	registryOption ftypes.RegistryOptions
	once           sync.Once // we need to update java-db once per run
}

func (u *Updater) Update() error {
	// logger object
	logger, _ := log.NewLogger(true, false)

	dbDir := u.dbDir
	metac := db.NewMetadata(dbDir)

	meta, err := metac.Get()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return xerrors.Errorf("Java DB metadata error: %w", err)
		} else if u.skip {
			log.Logger.Error("The first run cannot skip downloading Java DB")
			return xerrors.New("'--skip-java-db-update' cannot be specified on the first run")
		}
	}

	if (meta.Version != db.SchemaVersion || meta.NextUpdate.Before(time.Now().UTC())) && !u.skip {
		// Download DB
		log.Logger.Infof("Java DB Repository: %s", u.repo)
		logger.Info("downloading the Java DB...")

		// TODO: support remote options
		var a *oci.Artifact
		if a, err = oci.NewArtifact(u.repo, u.quiet, u.registryOption); err != nil {
			return xerrors.Errorf("oci error: %w", err)
		}
		if err = a.Download(context.Background(), dbDir, oci.DownloadOption{MediaType: mediaType}); err != nil {
			return xerrors.Errorf("DB download error: %w", err)
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
		logger.Infof("Java DB download complete. Last Updated At: %s", meta.UpdatedAt.String())

		log.Logger.Info("The Java DB is cached for 3 days. If you want to update the database more frequently, " +
			"the '--reset' flag clears the DB cache.")
	}

	return nil
}

func Init(cacheDir, javaDBRepository string, skip, quiet bool, registryOption ftypes.RegistryOptions) {
	updater = &Updater{
		repo:           fmt.Sprintf("%s:%d", javaDBRepository, db.SchemaVersion),
		dbDir:          filepath.Join(cacheDir, "java-db"),
		skip:           skip,
		quiet:          quiet,
		registryOption: registryOption,
	}
}

func NewUpdater(
	cacheDir, javaDBRepository string,
	skip, quiet bool,
	registryOption ftypes.RegistryOptions,
) *Updater {
	updater = &Updater{
		repo:           fmt.Sprintf("%s:%d", javaDBRepository, db.SchemaVersion),
		dbDir:          filepath.Join(cacheDir, "java-db"),
		skip:           skip,
		quiet:          quiet,
		registryOption: registryOption,
	}

	return updater
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

func getLicense(license string) string {
	// TODO: Figure out a way to return list since license strings can contain `,` . Trivy does not support it currently
	// Keeping it consistent for the time being
	return strings.ReplaceAll(license, "|", ",")
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
		License:    getLicense(index.License),
	}, nil
}

func (d *DB) SearchByGAV(groupID, artifactID, version string) (jar.Properties, error) {
	index, err := d.driver.SelectIndexByGAV(artifactID, groupID, version)
	if err != nil {
		return jar.Properties{}, xerrors.Errorf("select error: %w", err)
	} else if index.ArtifactID == "" {
		return jar.Properties{}, xerrors.Errorf("groupID %s: artifactID %s : version %s :  %w", groupID, artifactID, version, jar.ArtifactNotFoundErr)
	}
	return jar.Properties{
		GroupID:    index.GroupID,
		ArtifactID: index.ArtifactID,
		Version:    index.Version,
		License:    getLicense(index.License),
	}, nil
}

func (d *DB) SearchByArtifactID(artifactID string) (string, error) {
	indexes, err := d.driver.SelectIndexesByArtifactIDAndFileType(artifactID, types.JarType)
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
