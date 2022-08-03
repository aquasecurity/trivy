package utils

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"
)

const (
	xdgDataHome = "XDG_DATA_HOME"
)

var cacheDir string

// DefaultCacheDir returns/creates the cache-dir to be used for trivy operations
func DefaultCacheDir() string {
	tmpDir, err := os.UserCacheDir()
	if err != nil {
		tmpDir = os.TempDir()
	}
	return filepath.Join(tmpDir, "trivy")
}

// CacheDir returns the directory used for caching
func CacheDir() string {
	return cacheDir
}

// SetCacheDir sets the trivy cacheDir
func SetCacheDir(dir string) {
	cacheDir = dir
}

func HomeDir() string {
	dataHome := os.Getenv(xdgDataHome)
	if dataHome != "" {
		return dataHome
	}

	homeDir, _ := os.UserHomeDir()
	return homeDir
}

// CopyFile copies the file content from scr to dst
func CopyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, xerrors.Errorf("file (%s) stat error: %w", src, err)
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	n, err := io.Copy(destination, source)
	return n, err
}

// GetTLSConfig get tls config from CA, Cert and Key file
func GetTLSConfig(caCertPath, certPath, keyPath string) (*x509.CertPool, tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, tls.Certificate{}, err
	}

	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, tls.Certificate{}, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return caCertPool, cert, nil
}
