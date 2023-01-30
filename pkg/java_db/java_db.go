package java_db

import (
	"context"
	"path/filepath"
	"time"

	"github.com/aquasecurity/trivy-java-db/pkg/metadata"
	"github.com/aquasecurity/trivy/pkg/oci"

	"golang.org/x/xerrors"
)

const (
	defaultJavaDBRepository = "ghcr.io/dmitriylewen/trivy-java-db:latest"
	// defaultJavaDBRepository = "ghcr.io/aquasecurity/trivy-java-db:latest"
	mediaType = "application/vnd.aquasec.trivy.java.db.layer.v1.tar+gzip"
)

var (
	javaDBClient JavaDBClient
)

type JavaDBClient struct {
	ociArtifact *oci.Artifact
	cacheDir    string
}

func InitJavaDB(cacheDir string, quiet, insecure bool) error {
	a, err := oci.NewArtifact(defaultJavaDBRepository, mediaType, quiet, insecure)
	if err != nil {
		return xerrors.Errorf("trivy-java-db artifact initialize error: %w", err)
	}
	javaDBClient = JavaDBClient{
		ociArtifact: a,
		cacheDir:    filepath.Join(cacheDir + "/java-db"),
	}
	return nil
}

func UpdateJavaDB() (string, error) {
	dbDir := javaDBClient.cacheDir
	metadata.Init(javaDBClient.cacheDir)
	meta, err := metadata.Get()
	if err != nil {
		return "", err
	}
	if meta.NextUpdate.Before(time.Now().UTC()) {
		// download DB
		err = javaDBClient.ociArtifact.Download(context.Background(), javaDBClient.cacheDir)
		if err != nil {
			return "", xerrors.Errorf("trivy-java-db download error: %w", err)
		}
		// update DownloadedAt
		meta.DownloadedAt = time.Now().UTC()
		err = metadata.Update(meta)
		if err != nil {
			return "", err
		}
	}
	return dbDir, nil
}
