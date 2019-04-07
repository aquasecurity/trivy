package extractor

import (
	"archive/tar"
	"encoding/json"
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/knqyf263/nested"
	"golang.org/x/xerrors"
)

const (
	opq string = ".wh..wh..opq"
	wh  string = ".wh."
)

type manifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type opqDirs []string
type DockerExtractor struct{}

func (d DockerExtractor) Extract(r io.ReadCloser, filenames []string) (FileMap, error) {
	manifests := make([]manifest, 0)
	filesInLayers := make(map[string]FileMap)
	opqInLayers := make(map[string]opqDirs)

	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrCouldNotExtract
		}
		switch {
		case header.Name == "manifest.json":
			if err := json.NewDecoder(tr).Decode(&manifests); err != nil {
				return nil, err
			}
		case strings.HasSuffix(header.Name, ".tar"):
			layerID := filepath.Base(filepath.Dir(header.Name))
			files, opqDirs, err := d.ExtractFiles(tr, filenames)
			if err != nil {
				return nil, err
			}
			filesInLayers[layerID] = files
			opqInLayers[layerID] = opqDirs
		default:
		}
	}

	if len(manifests) == 0 {
		return nil, xerrors.New("Invalid image")
	}

	// Merge all layers
	sep := "/"
	nestedMap := nested.Nested{}
	for _, layerID := range manifests[0].Layers {
		layerID := strings.Split(layerID, sep)[0]
		for _, opqDir := range opqInLayers[layerID] {
			nestedMap.DeleteByString(opqDir, sep)
		}

		for filePath, content := range filesInLayers[layerID] {
			fileName := filepath.Base(filePath)
			fileDir := filepath.Dir(filePath)
			switch {
			case strings.HasPrefix(fileName, wh):
				fname := strings.TrimPrefix(fileName, wh)
				fpath := filepath.Join(fileDir, fname)
				nestedMap.DeleteByString(fpath, sep)
			default:
				nestedMap.SetByString(filePath, sep, content)
			}
		}
	}

	fileMap := FileMap{}
	walkFn := func(keys []string, value interface{}) error {
		content, ok := value.([]byte)
		if !ok {
			return nil
		}
		path := strings.Join(keys, "/")
		fileMap[path] = content
		return nil
	}
	if err := nestedMap.Walk(walkFn); err != nil {
		return nil, xerrors.Errorf("failed to walk nested map: %w", err)
	}

	return fileMap, nil

}
func (d DockerExtractor) ExtractFiles(layer io.Reader, filenames []string) (FileMap, opqDirs, error) {
	data := make(map[string][]byte)
	opqDirs := opqDirs{}

	tr := tar.NewReader(layer)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return data, nil, ErrCouldNotExtract
		}

		filePath := hdr.Name
		filePath = filepath.Clean(filePath)
		fileName := filepath.Base(filePath)

		// e.g. etc/.wh..wh..opq
		if opq == fileName {
			opqDirs = append(opqDirs, filepath.Dir(filePath))
			continue
		}

		// Determine if we should extract the element
		extract := false
		for _, s := range filenames {
			if s == filePath || strings.HasPrefix(fileName, wh) {
				extract = true
				break
			}
		}

		if !extract {
			continue
		}

		// Extract the element
		if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink || hdr.Typeflag == tar.TypeReg {
			d, err := ioutil.ReadAll(tr)
			if err != nil {
				return nil, nil, xerrors.Errorf("failed to read file: %w", err)
			}
			data[filePath] = d
		}
	}

	return data, opqDirs, nil

}
