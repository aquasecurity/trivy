package extractor

import (
	"archive/tar"
	"encoding/json"
	"io"
	"io/ioutil"
	"path"
	"path/filepath"
	"strings"
)

type manifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type DockerExtractor struct{}

func (d DockerExtractor) Extract(r io.ReadCloser, filenames []string) (FilesMap, error) {
	manifests := make([]manifest, 0)
	filesInLayers := make(map[string]FilesMap)
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
			files, err := d.ExtractFiles(tr, filenames)
			if err != nil {
				return nil, err
			}
			filesInLayers[layerID] = files
		//case strings.HasSuffix(header.Name, ".json"):
		//	if err := json.NewDecoder(tr).Decode(&imageMeta); err != nil {
		//		return nil, err
		//	}
		//	imageMetas[header.Name] = imageMeta
		default:
		}
	}
	filesMap := map[string][]byte{}
	for _, layerID := range manifests[0].Layers {
		layerID := strings.Split(layerID, "/")[0]
		for k, v := range filesInLayers[layerID] {
			filesMap[k] = v
		}
	}

	return filesMap, nil

}
func (d DockerExtractor) ExtractFiles(layer io.Reader, filenames []string) (FilesMap, error) {
	data := make(map[string][]byte)

	tr := tar.NewReader(layer)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return data, ErrCouldNotExtract
		}

		// Get element filename
		filename := hdr.Name
		filename = path.Clean(filename)

		// Determine if we should extract the element
		extract := false
		for _, s := range filenames {
			if s == filename {
				extract = true
				break
			}
		}

		if !extract {
			continue
		}

		// Extract the element
		if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink || hdr.Typeflag == tar.TypeReg {
			d, _ := ioutil.ReadAll(tr)
			data[filename] = d
		}
	}

	return data, nil

}
