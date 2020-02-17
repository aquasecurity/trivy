package docker

import (
	"archive/tar"
	"context"
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

	digest "github.com/opencontainers/go-digest"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/extractor/image"
	"github.com/aquasecurity/fanal/extractor/image/token/ecr"
	"github.com/aquasecurity/fanal/extractor/image/token/gcr"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"github.com/knqyf263/nested"
)

const (
	opq string = ".wh..wh..opq"
	wh  string = ".wh."
)

type Config struct {
	ContainerConfig containerConfig `json:"container_config"`
	History         []History
}

type containerConfig struct {
	Env []string
}

type History struct {
	Created   time.Time
	CreatedBy string `json:"created_by"`
}

type layer struct {
	id      digest.Digest
	content io.ReadCloser
	cleanup func()
}

type Extractor struct {
	option types.DockerOption
	cache  cache.Cache
}

func NewDockerExtractor(option types.DockerOption, c cache.Cache) Extractor {
	image.RegisterRegistry(&gcr.GCR{})
	image.RegisterRegistry(&ecr.ECR{})

	return Extractor{
		option: option,
		cache:  c,
	}
}

func applyLayers(layerPaths []string, filesInLayers map[string]extractor.FileMap, opqInLayers map[string]extractor.OPQDirs) (extractor.FileMap, error) {
	sep := "/"
	nestedMap := nested.Nested{}
	for _, layerPath := range layerPaths {
		for _, opqDir := range opqInLayers[layerPath] {
			nestedMap.DeleteByString(opqDir, sep)
		}

		for filePath, content := range filesInLayers[layerPath] {
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

	fileMap := extractor.FileMap{}
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

func (d Extractor) Extract(ctx context.Context, imgRef image.Reference, transports, filenames []string) (extractor.FileMap, error) {
	ctx, cancel := context.WithTimeout(ctx, d.option.Timeout)
	defer cancel()

	img, err := image.NewImage(ctx, imgRef, transports, d.option, d.cache)
	if err != nil {
		return nil, xerrors.Errorf("unable to initialize a image struct: %w", err)
	}

	defer img.Close()

	var layerIDs []string
	layers, err := img.LayerInfos()
	if err != nil {
		return nil, xerrors.Errorf("unable to get layer information: %w", err)
	}

	layerCh := make(chan layer)
	errCh := make(chan error)
	for _, l := range layers {
		layerIDs = append(layerIDs, string(l.Digest))
		go func(dig digest.Digest) {
			img, cleanup, err := img.GetBlob(ctx, dig)
			if err != nil {
				errCh <- xerrors.Errorf("failed to get a blob: %w", err)
				return
			}
			layerCh <- layer{id: dig, content: img, cleanup: cleanup}
		}(l.Digest)
	}

	filesInLayers := map[string]extractor.FileMap{}
	opqInLayers := map[string]extractor.OPQDirs{}
	for i := 0; i < len(layerIDs); i++ {
		if err := d.extractLayerFiles(ctx, layerCh, errCh, filesInLayers, opqInLayers, filenames); err != nil {
			return nil, xerrors.Errorf("failed to extract files from layer: %w", err)
		}
	}

	fileMap, err := applyLayers(layerIDs, filesInLayers, opqInLayers)
	if err != nil {
		return nil, xerrors.Errorf("failed to apply layers: %w", err)
	}

	// download config file
	config, err := img.ConfigBlob(ctx)
	if err != nil {
		return nil, xerrors.Errorf("failed to get a config blob: %w", err)
	}

	// special file for command analyzer
	fileMap["/config"] = config

	return fileMap, nil
}

func (d Extractor) extractLayerFiles(ctx context.Context, layerCh chan layer, errCh chan error,
	filesInLayers map[string]extractor.FileMap, opqInLayers map[string]extractor.OPQDirs, filenames []string) error {
	var l layer
	select {
	case l = <-layerCh:
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return xerrors.Errorf("timeout: %w", ctx.Err())
	}
	defer l.cleanup()

	files, opqDirs, err := d.ExtractFiles(l.content, filenames)
	if err != nil {
		return xerrors.Errorf("failed to extract files: %w", err)
	}

	layerID := string(l.id)
	filesInLayers[layerID] = files
	opqInLayers[layerID] = opqDirs

	return nil
}

func (d Extractor) ExtractFiles(layer io.Reader, filenames []string) (extractor.FileMap, extractor.OPQDirs, error) {
	data := make(map[string][]byte)
	opqDirs := extractor.OPQDirs{}

	tr := tar.NewReader(layer)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return data, nil, xerrors.Errorf("failed to extract the archive: %w", err)
		}

		filePath := hdr.Name
		filePath = strings.TrimLeft(filepath.Clean(filePath), "/")
		fileName := filepath.Base(filePath)

		// e.g. etc/.wh..wh..opq
		if opq == fileName {
			opqDirs = append(opqDirs, filepath.Dir(filePath))
			continue
		}

		if d.isIgnored(filePath) {
			continue
		}

		// Determine if we should extract the element
		extract := false
		for _, s := range filenames {
			// extract all files in target directory if last char is "/"(Separator)
			if s[len(s)-1] == '/' {
				if filepath.Clean(s) == filepath.Dir(filePath) {
					extract = true
					break
				}
			}

			if s == filePath || s == fileName || strings.HasPrefix(fileName, wh) {
				extract = true
				break
			}
		}

		if !extract {
			continue
		}

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

func (d Extractor) isIgnored(filePath string) bool {
	for _, path := range strings.Split(filePath, utils.PathSeparator) {
		if utils.StringInSlice(path, library.IgnoreDirs) {
			return true
		}
	}
	return false
}
