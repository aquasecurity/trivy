package docker

import (
	"archive/tar"
	"context"
	"io"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/knqyf263/nested"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/extractor/image"
	"github.com/aquasecurity/fanal/extractor/image/token/ecr"
	"github.com/aquasecurity/fanal/extractor/image/token/gcr"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
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

type Extractor struct {
	imageName string
	image     v1.Image
}

func init() {
	image.RegisterRegistry(&gcr.GCR{})
	image.RegisterRegistry(&ecr.ECR{})
}

func NewDockerExtractor(ctx context.Context, imageName string, option types.DockerOption) (Extractor, func(), error) {
	ctx, cancel := context.WithTimeout(ctx, option.Timeout)
	defer cancel()

	img, cleanup, err := image.NewDockerImage(ctx, imageName, option)
	if err != nil {
		return Extractor{}, nil, xerrors.Errorf("unable to initialize a image struct: %w", err)
	}

	return Extractor{
		imageName: imageName,
		image:     img,
	}, cleanup, nil
}

func NewDockerArchiveExtractor(ctx context.Context, fileName string, option types.DockerOption) (Extractor, error) {
	img, err := image.NewDockerArchiveImage(fileName)
	if err != nil {
		return Extractor{}, xerrors.Errorf("unable to initialize a image struct: %w", err)
	}

	return Extractor{
		imageName: fileName,
		image:     img,
	}, nil
}

func containsPackage(e types.Package, s []types.Package) bool {
	for _, a := range s {
		if a.Name == e.Name && a.Version == e.Version && a.Release == e.Release {
			return true
		}
	}
	return false
}

func containsLibrary(e godeptypes.Library, s []types.LibraryInfo) bool {
	for _, a := range s {
		if e.Name == a.Library.Name && e.Version == a.Library.Version {
			return true
		}
	}
	return false
}

func lookupOriginLayerForPkg(pkg types.Package, layers []types.LayerInfo) (string, string) {
	for _, layer := range layers {
		for _, info := range layer.PackageInfos {
			if containsPackage(pkg, info.Packages) {
				return layer.Digest, layer.DiffID
			}
		}
	}
	return "", ""
}

func lookupOriginLayerForLib(filePath string, lib godeptypes.Library, layers []types.LayerInfo) (string, string) {
	for _, layer := range layers {
		for _, layerApp := range layer.Applications {
			if filePath != layerApp.FilePath {
				continue
			}
			if containsLibrary(lib, layerApp.Libraries) {
				return layer.Digest, layer.DiffID
			}
		}
	}
	return "", ""
}

func ApplyLayers(layers []types.LayerInfo) types.ImageDetail {
	sep := "/"
	nestedMap := nested.Nested{}
	var mergedLayer types.ImageDetail

	for _, layer := range layers {
		for _, opqDir := range layer.OpaqueDirs {
			_ = nestedMap.DeleteByString(opqDir, sep)
		}
		for _, whFile := range layer.WhiteoutFiles {
			_ = nestedMap.DeleteByString(whFile, sep)
		}

		if layer.OS != nil {
			mergedLayer.OS = layer.OS
		}

		for _, pkgInfo := range layer.PackageInfos {
			nestedMap.SetByString(pkgInfo.FilePath, sep, pkgInfo)
		}
		for _, app := range layer.Applications {
			nestedMap.SetByString(app.FilePath, sep, app)
		}
	}

	_ = nestedMap.Walk(func(keys []string, value interface{}) error {
		switch v := value.(type) {
		case types.PackageInfo:
			mergedLayer.Packages = append(mergedLayer.Packages, v.Packages...)
		case types.Application:
			mergedLayer.Applications = append(mergedLayer.Applications, v)
		}
		return nil
	})

	for i, pkg := range mergedLayer.Packages {
		originLayerDigest, originLayerDiffID := lookupOriginLayerForPkg(pkg, layers)
		mergedLayer.Packages[i].Layer = types.Layer{
			Digest: originLayerDigest,
			DiffID: originLayerDiffID,
		}
	}

	for _, app := range mergedLayer.Applications {
		for i, libInfo := range app.Libraries {
			originLayerDigest, originLayerDiffID := lookupOriginLayerForLib(app.FilePath, libInfo.Library, layers)
			app.Libraries[i].Layer = types.Layer{
				Digest: originLayerDigest,
				DiffID: originLayerDiffID,
			}
		}
	}

	return mergedLayer
}

func (d Extractor) ImageName() string {
	return d.imageName
}

func (d Extractor) ImageID() (string, error) {
	h, err := d.image.ConfigName()
	if err != nil {
		return "", xerrors.Errorf("unable to get the image ID: %w", err)
	}
	return h.String(), nil
}

func (d Extractor) ConfigBlob() ([]byte, error) {
	return d.image.RawConfigFile()
}

func (d Extractor) LayerIDs() ([]string, error) {
	conf, err := d.image.ConfigFile()
	if err != nil {
		return nil, xerrors.Errorf("unable to get the config file: %w", err)
	}

	var layerIDs []string
	for _, d := range conf.RootFS.DiffIDs {
		layerIDs = append(layerIDs, d.String())
	}
	return layerIDs, nil
}

func (d Extractor) ExtractLayerFiles(diffID string, filenames []string) (string, extractor.FileMap, []string, []string, error) {
	// diffID is a hash of the uncompressed layer
	h, err := v1.NewHash(diffID)
	if err != nil {
		return "", nil, nil, nil, xerrors.Errorf("invalid layer ID (%s): %w", diffID, err)
	}

	layer, err := d.image.LayerByDiffID(h)
	if err != nil {
		return "", nil, nil, nil, xerrors.Errorf("failed to get the layer (%s): %w", diffID, err)
	}

	// digest is a hash of the compressed layer
	var digest string
	if d.isCompressed(layer) {
		d, err := layer.Digest()
		if err != nil {
			return "", nil, nil, nil, xerrors.Errorf("failed to get the digest (%s): %w", diffID, err)
		}
		digest = d.String()
	}

	r, err := layer.Uncompressed()
	if err != nil {
		return "", nil, nil, nil, xerrors.Errorf("failed to get the layer content (%s): %w", diffID, err)
	}

	files, opqDirs, whFiles, err := d.extractFiles(r, filenames)
	if err != nil {
		return "", nil, nil, nil, xerrors.Errorf("failed to extract files: %w", err)
	}

	return digest, files, opqDirs, whFiles, nil
}

// ref. https://github.com/google/go-containerregistry/issues/701
func (d Extractor) isCompressed(l v1.Layer) bool {
	_, uncompressed := reflect.TypeOf(l).Elem().FieldByName("UncompressedLayer")
	return !uncompressed
}

func (d Extractor) extractFiles(layer io.Reader, filenames []string) (extractor.FileMap, []string, []string, error) {
	data := make(map[string][]byte)
	var opqDirs, whFiles []string

	tr := tar.NewReader(layer)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return data, nil, nil, xerrors.Errorf("failed to extract the archive: %w", err)
		}

		filePath := hdr.Name
		filePath = strings.TrimLeft(filepath.Clean(filePath), "/")
		fileDir, fileName := filepath.Split(filePath)

		// e.g. etc/.wh..wh..opq
		if opq == fileName {
			opqDirs = append(opqDirs, fileDir)
			continue
		}
		// etc/.wh.hostname
		if strings.HasPrefix(fileName, wh) {
			name := strings.TrimPrefix(fileName, wh)
			fpath := filepath.Join(fileDir, name)
			whFiles = append(whFiles, fpath)
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

			if s == filePath || s == fileName {
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
				return nil, nil, nil, xerrors.Errorf("failed to read file: %w", err)
			}
			data[filePath] = d
		}
	}

	return data, opqDirs, whFiles, nil
}

func (d Extractor) isIgnored(filePath string) bool {
	for _, path := range strings.Split(filePath, utils.PathSeparator) {
		if utils.StringInSlice(path, library.IgnoreDirs) {
			return true
		}
	}
	return false
}
