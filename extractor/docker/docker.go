package docker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/extractor/docker/token/ecr"
	"github.com/aquasecurity/fanal/extractor/docker/token/gcr"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/docker/docker/client"
	"github.com/genuinetools/reg/registry"
	"github.com/klauspost/compress/zstd"
	"github.com/knqyf263/nested"
	"github.com/opencontainers/go-digest"
	"golang.org/x/xerrors"
)

const (
	opq string = ".wh..wh..opq"
	wh  string = ".wh."

	KVImageBucket   string = "imagebucket"
	LayerTarsBucket string = "layertars"
)

var (
	ErrFailedCacheWrite = errors.New("failed to write to cache")
)

type manifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

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
	ID      digest.Digest
	Content io.ReadCloser
}

type Extractor struct {
	Client *client.Client
	Option types.DockerOption
	cache  cache.Cache
}

func NewDockerExtractor(option types.DockerOption, cache cache.Cache) (Extractor, error) {
	RegisterRegistry(&gcr.GCR{})
	RegisterRegistry(&ecr.ECR{})

	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return Extractor{}, xerrors.Errorf("error initializing docker extractor: %w", err)
	}

	return Extractor{
		Option: option,
		Client: cli,
		cache:  cache,
	}, nil
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

func (d Extractor) createRegistryClient(ctx context.Context, domain string) (*registry.Registry, error) {
	auth, err := GetToken(ctx, domain, d.Option)
	if err != nil {
		return nil, xerrors.Errorf("failed to get auth config: %w", err)
	}

	// Prevent non-ssl unless explicitly forced
	if !d.Option.NonSSL && strings.HasPrefix(auth.ServerAddress, "http:") {
		return nil, xerrors.New("attempted to use insecure protocol! Use force-non-ssl option to force")
	}

	// Create the registry client.
	return registry.New(ctx, auth, registry.Opt{
		Domain:   domain,
		Insecure: d.Option.Insecure,
		Debug:    d.Option.Debug,
		SkipPing: d.Option.SkipPing,
		NonSSL:   d.Option.NonSSL,
		Timeout:  d.Option.Timeout,
	})
}

func (d Extractor) SaveLocalImage(ctx context.Context, imageName string) (io.Reader, error) {
	var storedReader io.Reader

	var storedImageBytes []byte
	found, err := d.cache.Get(KVImageBucket, imageName, &storedImageBytes)

	if found {
		dec, _ := zstd.NewReader(nil)
		storedImage, err := dec.DecodeAll(storedImageBytes, nil)
		if err == nil {
			return bytes.NewReader(storedImage), nil
		}

		// bad cache, redownload
		found = false
	}

	var savedImage []byte
	if err != nil || !found {
		storedReader, err = d.saveLocalImage(ctx, imageName)
		if err != nil {
			return nil, xerrors.Errorf("failed to save the image: %w", err)
		}

		savedImage, err = ioutil.ReadAll(storedReader)
		if err != nil {
			return nil, xerrors.Errorf("failed to read saved image: %w", err)
		}

		e, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
		if err != nil {
			return nil, err
		}

		dst := e.EncodeAll(savedImage, nil)
		if err := d.cache.Set(KVImageBucket, imageName, dst); err != nil {
			log.Println(err)
		}
	}

	return bytes.NewReader(savedImage), nil
}

func (d Extractor) saveLocalImage(ctx context.Context, imageName string) (io.ReadCloser, error) {
	r, err := d.Client.ImageSave(ctx, []string{imageName})
	if err != nil {
		return nil, xerrors.New("error in docker image save")
	}
	return r, nil
}

func (d Extractor) Extract(ctx context.Context, imageName string, filenames []string) (extractor.FileMap, error) {
	ctx, cancel := context.WithTimeout(ctx, d.Option.Timeout)
	defer cancel()

	image, err := registry.ParseImage(imageName)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse the image: %w", err)
	}
	r, err := d.createRegistryClient(ctx, image.Domain)
	if err != nil {
		return nil, xerrors.Errorf("failed to create the registry client: %w", err)
	}

	// Get the v2 manifest.
	m, err := getValidManifest(ctx, r, image)
	if err != nil {
		return nil, err
	}

	layerCh := make(chan layer)
	errCh := make(chan error)
	var layerIDs []string

	for _, ref := range m.Manifest.Layers {
		layerIDs = append(layerIDs, string(ref.Digest))
		go func(dig digest.Digest) {
			d.extractLayerWorker(dig, r, ctx, image, errCh, layerCh, filenames)
		}(ref.Digest)
	}

	filesInLayers := map[string]extractor.FileMap{}
	opqInLayers := map[string]extractor.OPQDirs{}
	for i := 0; i < len(m.Manifest.Layers); i++ {
		if err := d.extractLayerFiles(ctx, layerCh, errCh, filesInLayers, opqInLayers, filenames); err != nil {
			return nil, err
		}
	}

	fileMap, err := applyLayers(layerIDs, filesInLayers, opqInLayers)
	if err != nil {
		return nil, xerrors.Errorf("failed to apply layers: %w", err)
	}

	// download config file
	config, err := downloadConfigFile(ctx, r, image, m)
	if err != nil {
		return nil, err
	}

	// special file for command analyzer
	fileMap["/config"] = config

	return fileMap, nil
}

func downloadConfigFile(ctx context.Context, r *registry.Registry, image registry.Image, m *schema2.DeserializedManifest) ([]byte, error) {
	rc, err := r.DownloadLayer(ctx, image.Path, m.Manifest.Config.Digest)
	if err != nil {
		return nil, xerrors.Errorf("error in layer download: %w", err)
	}
	config, err := ioutil.ReadAll(rc)
	if err != nil {
		return nil, xerrors.Errorf("failed to decode config JSON: %w", err)
	}
	return config, nil
}

func (d Extractor) extractLayerFiles(ctx context.Context, layerCh chan layer, errCh chan error, filesInLayers map[string]extractor.FileMap, opqInLayers map[string]extractor.OPQDirs, filenames []string) error {
	var l layer
	select {
	case l = <-layerCh:
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return xerrors.Errorf("timeout: %w", ctx.Err())
	}
	files, opqDirs, err := d.ExtractFiles(l.Content, filenames)
	if err != nil {
		return xerrors.Errorf("failed to extract files: %w", err)
	}
	layerID := string(l.ID)
	filesInLayers[layerID] = files
	opqInLayers[layerID] = opqDirs

	return nil
}

func (d Extractor) extractLayerWorker(dig digest.Digest, r *registry.Registry, ctx context.Context, image registry.Image, errCh chan error, layerCh chan layer, filenames []string) {
	var tarContent bytes.Buffer
	var cacheContent []byte
	var cacheBuf bytes.Buffer

	found, _ := d.cache.Get(LayerTarsBucket, string(dig), &cacheContent)

	if found {
		b, errTar := extractTarFromTarZstd(cacheContent)
		n, errWrite := cacheBuf.Write(b)
		if errTar != nil || len(b) <= 0 || errWrite != nil || n <= 0 {
			found = false
		}
	}

	if !found {
		rc, err := r.DownloadLayer(ctx, image.Path, dig)
		if err != nil {
			errCh <- xerrors.Errorf("failed to download the layer(%s): %w", dig, err)
			return
		}
		defer rc.Close()

		// read the incoming gzip from the layer
		gzipReader, err := gzip.NewReader(rc)
		if err != nil {
			errCh <- xerrors.Errorf("could not init gzip reader: %w", err)
			return
		}
		defer gzipReader.Close()

		tarReader := tar.NewReader(io.TeeReader(gzipReader, &tarContent))

		if len(filenames) > 0 {
			if cacheBuf, err = getFilteredTarballBuffer(tarReader, filenames); err != nil {
				errCh <- err
				return
			}
		}

		d.storeLayerInCache(cacheBuf, dig)
	}

	layerCh <- layer{ID: dig, Content: ioutil.NopCloser(&cacheBuf)}
	return
}

func extractTarFromTarZstd(cacheContent []byte) ([]byte, error) {
	var tarContent []byte

	dec, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}

	tarContent, err = dec.DecodeAll(cacheContent, nil)
	if err != nil {
		return nil, err
	}

	return tarContent, nil
}

func getFilteredTarballBuffer(tr *tar.Reader, requiredFilenames []string) (bytes.Buffer, error) {
	var cacheBuf bytes.Buffer
	// Create a new tar to store in the cache
	twc := tar.NewWriter(&cacheBuf)
	defer twc.Close()

	// check what files are inside the tar
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // end of archive
		}
		if err != nil {
			return cacheBuf, xerrors.Errorf("%s: invalid tar: %w", ErrFailedCacheWrite, err)
		}
		if !utils.StringInSlice(hdr.Name, requiredFilenames) {
			continue
		}

		hdrtwc := &tar.Header{
			Name: hdr.Name,
			Mode: 0600,
			Size: hdr.Size,
		}

		if err := twc.WriteHeader(hdrtwc); err != nil {
			return cacheBuf, xerrors.Errorf("%s: %s", ErrFailedCacheWrite, err)
		}

		_, err = io.Copy(twc, tr)
		if err != nil {
			return cacheBuf, xerrors.Errorf("%s: %s", ErrFailedCacheWrite, err)
		}
	}
	return cacheBuf, nil
}

func (d Extractor) storeLayerInCache(cacheBuf bytes.Buffer, dig digest.Digest) {
	// compress tar to zstd before storing to cache
	var dst bytes.Buffer
	w, _ := zstd.NewWriter(&dst, zstd.WithEncoderLevel(zstd.SpeedFastest))
	_, _ = io.Copy(w, &cacheBuf)
	_ = w.Close()

	if err := d.cache.Set(LayerTarsBucket, string(dig), dst.Bytes()); err != nil {
		log.Printf("an error occurred while caching: %s", err)
	}
}

func getValidManifest(ctx context.Context, r *registry.Registry, image registry.Image) (*schema2.DeserializedManifest, error) {
	manifest, err := r.Manifest(ctx, image.Path, image.Reference())
	if err != nil {
		return nil, xerrors.Errorf("failed to get the v2 manifest: %w", err)
	}
	m, ok := manifest.(*schema2.DeserializedManifest)
	if !ok {
		return nil, xerrors.New("invalid manifest")
	}
	return m, nil
}

func (d Extractor) ExtractFromFile(ctx context.Context, r io.Reader, filenames []string) (extractor.FileMap, error) {
	manifests := make([]manifest, 0)
	filesInLayers := map[string]extractor.FileMap{}
	opqInLayers := make(map[string]extractor.OPQDirs)

	tarFiles := make(map[string][]byte)

	// Extract the files from the tarball
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, xerrors.Errorf("failed to extract the archive: %w", err)
		}

		switch {
		case header.Name == "manifest.json":
			if err := json.NewDecoder(tr).Decode(&manifests); err != nil {
				return nil, xerrors.Errorf("failed to decode manifest JSON: %w", err)
			}
		case strings.HasSuffix(header.Name, ".tar"):
			files, opqDirs, err := d.ExtractFiles(tr, filenames)
			if err != nil {
				return nil, err
			}

			filesInLayers[header.Name] = files
			opqInLayers[header.Name] = opqDirs
		case strings.HasSuffix(header.Name, ".tar.gz"):
			gzipReader, err := gzip.NewReader(tr)
			if err != nil {
				return nil, err
			}
			files, opqDirs, err := d.ExtractFiles(gzipReader, filenames)
			if err != nil {
				return nil, err
			}

			filesInLayers[header.Name] = files
			opqInLayers[header.Name] = opqDirs
		default:
			// save all JSON temporarily for config JSON
			tarFiles[header.Name], err = ioutil.ReadAll(tr)
			if err != nil {
				return nil, xerrors.Errorf("failed to read a file: %w", err)
			}
		}
	}

	if len(manifests) == 0 {
		return nil, xerrors.New("Invalid manifest file")
	}

	fileMap, err := applyLayers(manifests[0].Layers, filesInLayers, opqInLayers)
	if err != nil {
		return nil, xerrors.Errorf("failed to apply layers: %w", err)
	}

	// special file for command analyzer
	data, ok := tarFiles[manifests[0].Config]
	if !ok {
		return nil, xerrors.Errorf("Image config: %s not found\n", manifests[0].Config)
	}
	fileMap["/config"] = data

	return fileMap, nil
}

func (d Extractor) ExtractFiles(layerReader io.Reader, filenames []string) (extractor.FileMap, extractor.OPQDirs, error) {
	data := make(map[string][]byte)
	opqDirs := extractor.OPQDirs{}

	tr := tar.NewReader(layerReader)
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
