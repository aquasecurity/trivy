package java_db

import (
	"context"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/pkg/oci"
	"golang.org/x/xerrors"
	"path/filepath"
	"time"
)

const (
	defaultJavaDBRepository = "ghcr.io/dmitriylewen/trivy-java-db:latest"
	mediaType               = "application/vnd.aquasec.trivy.java.db.layer.v1.tar+gzip"
)

var (
	javaDBClient JavaDBClient
)

type JavaDBClient struct {
	ociArtifact *oci.Artifact
	cacheDir    string
	quiet       bool
	insecure    bool
}

func InitJavaDB(cacheDir string, quiet, insecure bool) error {
	a, err := oci.NewArtifact(defaultJavaDBRepository, mediaType, quiet, insecure)
	if err != nil {
		return xerrors.Errorf("trivy-java-db artifact initialize error: %w", err)
	}
	javaDBClient = JavaDBClient{
		ociArtifact: a,
		cacheDir:    filepath.Join(cacheDir + "/java-db"),
		quiet:       quiet,
		insecure:    insecure,
	}
	return nil
}

func UpdateJavaDB() (string, error) {
	dbDir := filepath.Join(javaDBClient.cacheDir, "db")
	c := metadata.NewClient(javaDBClient.cacheDir) // TODO use metadata from trivy-java-db
	meta, err := c.Get()
	if err != nil || meta.NextUpdate.Before(time.Now().UTC()) {
		err = downloadTrivyJavaDB(dbDir, javaDBClient.quiet, javaDBClient.insecure) // TODO add flags
		if err != nil {
			return "", err
		}
	}
	return dbDir, nil
}

func downloadTrivyJavaDB(cacheDir string, quiet, insecure bool) error {
	artifact, err := oci.NewArtifact(defaultJavaDBRepository, mediaType, quiet, insecure)
	if err != nil {
		return xerrors.Errorf("trivy-java-db artifact initialize error: %w", err) // TODO change this!!!
	}
	err = artifact.Download(context.Background(), cacheDir)
	if err != nil {
		return xerrors.Errorf("trivy-java-db download error: %w", err)
	}
	return nil
}
