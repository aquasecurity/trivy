package integration_test

import (
	"compress/gzip"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

func gunzipDB() string {
	gz, err := os.Open("testdata/trivy.db.gz")
	if err != nil {
		log.Panic(err)
	}
	zr, err := gzip.NewReader(gz)
	if err != nil {
		log.Panic(err)
	}

	tmpDir, err := ioutil.TempDir("", "integration")
	if err != nil {
		log.Panic(err)
	}
	dbDir := filepath.Join(tmpDir, "db")
	err = os.MkdirAll(dbDir, 0700)
	if err != nil {
		log.Panic(err)
	}

	file, err := os.Create(filepath.Join(dbDir, "trivy.db"))
	if err != nil {
		log.Panic(err)
	}
	defer file.Close()

	_, err = io.Copy(file, zr)
	if err != nil {
		log.Panic(err)
	}
	return tmpDir
}
