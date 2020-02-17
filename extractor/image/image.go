package image

import (
	"context"
	"encoding/json"
	"io"
	"io/ioutil"

	"github.com/containers/image/image"
	"github.com/containers/image/pkg/blobinfocache"
	"github.com/containers/image/pkg/compression"
	"github.com/containers/image/transports/alltransports"
	imageTypes "github.com/containers/image/types"
	"github.com/docker/distribution/reference"
	digest "github.com/opencontainers/go-digest"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
)

type ImageSource interface {
	GetBlob(ctx context.Context, info imageTypes.BlobInfo, cache imageTypes.BlobInfoCache) (reader io.ReadCloser, n int64, err error)
	Close() error
}

type ImageCloser interface {
	LayerInfos() (layerInfos []imageTypes.BlobInfo)
	ConfigBlob(ctx context.Context) (blob []byte, err error)
	Close() error
}

type Reference struct {
	Name   string
	IsFile bool
}

type Image struct {
	name       string   // e.g. alpine:3.10
	isFile     bool     // from a tar file
	transports []string // e.g. "docker://"

	systemContext *imageTypes.SystemContext
	blobInfoCache imageTypes.BlobInfoCache
	rawSource     ImageSource
	src           ImageCloser

	cache cache.Cache
}

func NewImage(ctx context.Context, image Reference, transports []string, option types.DockerOption,
	c cache.Cache) (Image, error) {
	var domain string
	var auth *imageTypes.DockerAuthConfig

	if !image.IsFile {
		named, err := reference.ParseNormalizedNamed(image.Name)
		if err != nil {
			return Image{}, xerrors.Errorf("invalid image name: %w", err)
		}

		// add 'latest' tag
		named = reference.TagNameOnly(named)
		image.Name = named.String()

		// get a credential for Docker registry
		domain = reference.Domain(named)
		auth = GetToken(ctx, domain, option)
	}

	sys := &imageTypes.SystemContext{
		// TODO: make OSChoice configurable
		OSChoice:                          "linux",
		DockerAuthConfig:                  auth,
		DockerDisableV1Ping:               option.SkipPing,
		DockerInsecureSkipTLSVerify:       imageTypes.NewOptionalBool(option.InsecureSkipTLSVerify),
		OCIInsecureSkipTLSVerify:          option.InsecureSkipTLSVerify,
		DockerDaemonInsecureSkipTLSVerify: option.InsecureSkipTLSVerify,
	}

	return Image{
		name:       image.Name,
		isFile:     image.IsFile,
		transports: transports,

		systemContext: sys,
		blobInfoCache: blobinfocache.DefaultCache(sys),

		cache: c,
	}, nil
}

func (img *Image) populateSource() error {
	if img.rawSource != nil && img.src != nil {
		return nil
	}
	ctx := context.Background()
	err := xerrors.New("no valid transport")
	for _, transport := range img.transports {
		imgName := transport + img.name
		var ref imageTypes.ImageReference
		ref, err = alltransports.ParseImageName(imgName)
		if err != nil {
			return xerrors.Errorf("failed to parse an image name: %w", err)
		}

		var rawSource imageTypes.ImageSource
		rawSource, err = ref.NewImageSource(ctx, img.systemContext)
		if err != nil {
			// try next transport
			continue
		}

		var src imageTypes.ImageCloser
		src, err = image.FromSource(ctx, img.systemContext, rawSource)
		if err != nil {
			return xerrors.Errorf("failed to initialize: %w", err)
		}

		img.rawSource = rawSource
		img.src = src
		return nil
	}
	// return only the last error
	return err
}

func (img *Image) LayerInfos() ([]imageTypes.BlobInfo, error) {
	// ignore the cache error
	layerInfos, _ := img.getLayerInfosInCache(img.name, img.isFile)
	if layerInfos != nil {
		return layerInfos, nil
	}

	// When it doesn't hit a cache, it fetches the image from Docker Engine or Docker Registry
	if err := img.populateSource(); err != nil {
		return nil, xerrors.Errorf("failed population: %w", err)
	}

	layers := img.src.LayerInfos()

	// ignore the cache error
	_ = img.storeLayerInfosInCache(img.name, img.isFile, layers)

	return layers, nil
}

func (img Image) getLayerInfosInCache(imageName string, isFile bool) ([]imageTypes.BlobInfo, error) {
	// tar file doesn't have info in cache
	if isFile {
		return nil, nil
	}
	rc := img.cache.Get("layerinfos::" + imageName)
	if rc == nil {
		return nil, nil
	}
	var layerInfos []imageTypes.BlobInfo
	if err := json.NewDecoder(rc).Decode(&layerInfos); err != nil {
		return nil, xerrors.Errorf("invalid cache: %w", err)
	}
	return layerInfos, nil
}

func (img Image) storeLayerInfosInCache(imageName string, isFile bool, layers []imageTypes.BlobInfo) error {
	// it doesn't store the information of a tar file
	if isFile {
		return nil
	}

	b, err := json.Marshal(layers)
	if err != nil {
		return xerrors.Errorf("invalid json: %w", err)
	}
	return img.cache.SetBytes("layerinfos::"+imageName, b)
}

func (img *Image) ConfigBlob(ctx context.Context) ([]byte, error) {
	b, _ := img.getConfigBlobInCache(img.name, img.isFile)
	if b != nil {
		return b, nil
	}

	if err := img.populateSource(); err != nil {
		return nil, xerrors.Errorf("failed population: %w", err)
	}

	blob, err := img.src.ConfigBlob(ctx)
	if err != nil {
		return nil, xerrors.Errorf("failed to get a config: %w", err)
	}

	if !img.isFile {
		_ = img.cache.SetBytes("configblob::"+img.name, blob)
	}

	return blob, nil
}

func (img Image) getConfigBlobInCache(imageName string, isFile bool) ([]byte, error) {
	// tar file doesn't have info in cache
	if isFile {
		return nil, nil
	}
	rc := img.cache.Get("configblob::" + imageName)
	if rc == nil {
		return nil, nil
	}
	b, err := ioutil.ReadAll(rc)
	if err != nil {
		return nil, xerrors.Errorf("unable to read a cache file: %w", err)
	}
	return b, nil
}

func (img *Image) GetBlob(ctx context.Context, dig digest.Digest) (io.ReadCloser, func(), error) {
	rc := img.cache.Get(dig.String())
	if rc != nil {
		cleanup := func() { _ = rc.Close() }
		return rc, cleanup, nil
	}

	if err := img.populateSource(); err != nil {
		return nil, nil, xerrors.Errorf("failed population: %w", err)
	}

	rc, _, err := img.rawSource.GetBlob(ctx, imageTypes.BlobInfo{Digest: dig, Size: -1}, img.blobInfoCache)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to download the layer(%s): %w", dig, err)
	}

	stream, _, err := compression.AutoDecompress(rc)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to download the layer(%s): %w", dig, err)
	}
	cleanup := func() { _ = stream.Close() }

	r, _ := img.cache.Set(dig.String(), stream)

	return ioutil.NopCloser(r), cleanup, nil
}

func (img *Image) Close() {
	if img.src != nil {
		img.src.Close()
	}
	if img.rawSource != nil {
		img.rawSource.Close()
	}
}
