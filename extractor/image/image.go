package image

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/tls"
	"io"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/hashicorp/go-multierror"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/extractor/image/daemon"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

func NewDockerImage(ctx context.Context, imageName string, option types.DockerOption) (v1.Image, func(), error) {
	var result error

	var nameOpts []name.Option
	if option.NonSSL {
		nameOpts = append(nameOpts, name.Insecure)
	}
	ref, err := name.ParseReference(imageName, nameOpts...)
	if err != nil {
		return nil, func() {}, xerrors.Errorf("failed to parse the image name: %w", err)
	}

	// Try accessing Docker Daemon
	img, cleanup, err := daemon.Image(ref)
	if err == nil {
		// Return v1.Image if the image is found in Docker Engine
		return img, cleanup, nil
	}
	result = multierror.Append(result, err)

	// Try accessing Docker Registry
	var remoteOpts []remote.Option
	if option.InsecureSkipTLSVerify {
		t := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		remoteOpts = append(remoteOpts, remote.WithTransport(t))
	}

	domain := ref.Context().RegistryStr()
	auth := GetToken(ctx, domain, option)

	if auth.Username != "" && auth.Password != "" {
		remoteOpts = append(remoteOpts, remote.WithAuth(&auth))
	} else {
		remoteOpts = append(remoteOpts, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	}

	img, err = remote.Image(ref, remoteOpts...)
	if err == nil {
		// Return v1.Image if the image is found in Docker Registry
		return img, func() {}, nil
	}
	result = multierror.Append(result, err)

	return nil, func() {}, result
}

func NewArchiveImage(fileName string) (v1.Image, error) {
	var result error
	img, err := tryDockerArchive(fileName)
	if err == nil {
		// Return v1.Image if the file can be opened as Docker archive
		return img, nil
	}
	result = multierror.Append(result, err)

	img, err = tryOCI(fileName)
	if err == nil {
		// Return v1.Image if the directory can be opened as OCI Image Format
		return img, nil
	}
	result = multierror.Append(result, err)

	return nil, result
}

func tryDockerArchive(fileName string) (v1.Image, error) {
	img, err := tarball.Image(fileOpener(fileName), nil)
	if err != nil {
		return nil, xerrors.Errorf("unable to open %s as a Docker image: %w", fileName, err)
	}
	return img, nil
}

func fileOpener(fileName string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		f, err := os.Open(fileName)
		if err != nil {
			return nil, xerrors.Errorf("unable to open the file: %w", err)
		}

		var r io.Reader
		br := bufio.NewReader(f)
		r = br

		if utils.IsGzip(br) {
			r, err = gzip.NewReader(br)
			if err != nil {
				return nil, xerrors.Errorf("failed to open gzip: %w", err)
			}
		}
		return ioutil.NopCloser(r), nil
	}
}

func tryOCI(fileName string) (v1.Image, error) {
	lp, err := layout.FromPath(fileName)
	if err != nil {
		return nil, xerrors.Errorf("unable to open %s as an OCI Image: %w", fileName, err)
	}

	index, err := lp.ImageIndex()
	if err != nil {
		return nil, xerrors.Errorf("unable to retrieve index.json: %w", err)
	}

	m, err := index.IndexManifest()
	if err != nil {
		return nil, xerrors.Errorf("invalid index.json: %w", err)
	}

	if len(m.Manifests) == 0 {
		return nil, xerrors.New("no valid manifest")
	}

	// Support only first image
	h := m.Manifests[0].Digest
	img, err := index.Image(h)
	if err != nil {
		return nil, xerrors.New("invalid OCI image")
	}

	return img, nil
}
