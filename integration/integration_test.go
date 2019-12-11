// +build integration

package integration

import (
	"compress/gzip"
	"context"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"
)

var update = flag.Bool("update", false, "update golden files")

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

func getFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitPort(ctx context.Context, addr string) error {
	for {
		conn, err := net.Dial("tcp", addr)
		if err == nil && conn != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return err
		default:
			time.Sleep(1 * time.Second)
		}
	}
}
