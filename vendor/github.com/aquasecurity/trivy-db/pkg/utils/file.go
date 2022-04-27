package utils

import (
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"
)

func FileWalk(root string, walkFn func(r io.Reader, path string) error) error {
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		} else if d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return xerrors.Errorf("file info error: %w", err)
		}

		if info.Size() == 0 {
			log.Printf("invalid size: %s\n", path)
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return xerrors.Errorf("failed to open file: %w", err)
		}
		defer f.Close()

		if err = walkFn(f, path); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("file walk error: %w", err)
	}
	return nil
}

func Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func UnmarshalJSONFile(v interface{}, fileName string) error {
	f, err := os.Open(fileName)
	if err != nil {
		return xerrors.Errorf("unable to open a file (%s): %w", fileName, err)
	}
	defer f.Close()

	if err = json.NewDecoder(f).Decode(v); err != nil {
		return xerrors.Errorf("failed to decode file (%s): %w", fileName, err)
	}
	return nil
}
