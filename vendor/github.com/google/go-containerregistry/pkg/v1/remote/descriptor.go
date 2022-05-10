// Copyright 2018 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package remote

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/go-containerregistry/internal/verify"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// ErrSchema1 indicates that we received a schema1 manifest from the registry.
// This library doesn't have plans to support this legacy image format:
// https://github.com/google/go-containerregistry/issues/377
type ErrSchema1 struct {
	schema string
}

// newErrSchema1 returns an ErrSchema1 with the unexpected MediaType.
func newErrSchema1(schema types.MediaType) error {
	return &ErrSchema1{
		schema: string(schema),
	}
}

// Error implements error.
func (e *ErrSchema1) Error() string {
	return fmt.Sprintf("unsupported MediaType: %q, see https://github.com/google/go-containerregistry/issues/377", e.schema)
}

// Descriptor provides access to metadata about remote artifact and accessors
// for efficiently converting it into a v1.Image or v1.ImageIndex.
type Descriptor struct {
	fetcher
	v1.Descriptor
	Manifest []byte

	// So we can share this implementation with Image..
	platform v1.Platform
}

// RawManifest exists to satisfy the Taggable interface.
func (d *Descriptor) RawManifest() ([]byte, error) {
	return d.Manifest, nil
}

// Get returns a remote.Descriptor for the given reference. The response from
// the registry is left un-interpreted, for the most part. This is useful for
// querying what kind of artifact a reference represents.
//
// See Head if you don't need the response body.
func Get(ref name.Reference, options ...Option) (*Descriptor, error) {
	acceptable := []types.MediaType{
		// Just to look at them.
		types.DockerManifestSchema1,
		types.DockerManifestSchema1Signed,
	}
	acceptable = append(acceptable, acceptableImageMediaTypes...)
	acceptable = append(acceptable, acceptableIndexMediaTypes...)
	return get(ref, acceptable, options...)
}

// Head returns a v1.Descriptor for the given reference by issuing a HEAD
// request.
//
// Note that the server response will not have a body, so any errors encountered
// should be retried with Get to get more details.
func Head(ref name.Reference, options ...Option) (*v1.Descriptor, error) {
	acceptable := []types.MediaType{
		// Just to look at them.
		types.DockerManifestSchema1,
		types.DockerManifestSchema1Signed,
	}
	acceptable = append(acceptable, acceptableImageMediaTypes...)
	acceptable = append(acceptable, acceptableIndexMediaTypes...)

	o, err := makeOptions(ref.Context(), options...)
	if err != nil {
		return nil, err
	}

	f, err := makeFetcher(ref, o)
	if err != nil {
		return nil, err
	}

	return f.headManifest(ref, acceptable)
}

// Handle options and fetch the manifest with the acceptable MediaTypes in the
// Accept header.
func get(ref name.Reference, acceptable []types.MediaType, options ...Option) (*Descriptor, error) {
	o, err := makeOptions(ref.Context(), options...)
	if err != nil {
		return nil, err
	}
	f, err := makeFetcher(ref, o)
	if err != nil {
		return nil, err
	}
	b, desc, err := f.fetchManifest(ref, acceptable)
	if err != nil {
		return nil, err
	}
	return &Descriptor{
		fetcher:    *f,
		Manifest:   b,
		Descriptor: *desc,
		platform:   o.platform,
	}, nil
}

// Image converts the Descriptor into a v1.Image.
//
// If the fetched artifact is already an image, it will just return it.
//
// If the fetched artifact is an index, it will attempt to resolve the index to
// a child image with the appropriate platform.
//
// See WithPlatform to set the desired platform.
func (d *Descriptor) Image() (v1.Image, error) {
	switch d.MediaType {
	case types.DockerManifestSchema1, types.DockerManifestSchema1Signed:
		// We don't care to support schema 1 images:
		// https://github.com/google/go-containerregistry/issues/377
		return nil, newErrSchema1(d.MediaType)
	case types.OCIImageIndex, types.DockerManifestList:
		// We want an image but the registry has an index, resolve it to an image.
		return d.remoteIndex().imageByPlatform(d.platform)
	case types.OCIManifestSchema1, types.DockerManifestSchema2:
		// These are expected. Enumerated here to allow a default case.
	default:
		// We could just return an error here, but some registries (e.g. static
		// registries) don't set the Content-Type headers correctly, so instead...
		logs.Warn.Printf("Unexpected media type for Image(): %s", d.MediaType)
	}

	// Wrap the v1.Layers returned by this v1.Image in a hint for downstream
	// remote.Write calls to facilitate cross-repo "mounting".
	imgCore, err := partial.CompressedToImage(d.remoteImage())
	if err != nil {
		return nil, err
	}
	return &mountableImage{
		Image:     imgCore,
		Reference: d.Ref,
	}, nil
}

// ImageIndex converts the Descriptor into a v1.ImageIndex.
func (d *Descriptor) ImageIndex() (v1.ImageIndex, error) {
	switch d.MediaType {
	case types.DockerManifestSchema1, types.DockerManifestSchema1Signed:
		// We don't care to support schema 1 images:
		// https://github.com/google/go-containerregistry/issues/377
		return nil, newErrSchema1(d.MediaType)
	case types.OCIManifestSchema1, types.DockerManifestSchema2:
		// We want an index but the registry has an image, nothing we can do.
		return nil, fmt.Errorf("unexpected media type for ImageIndex(): %s; call Image() instead", d.MediaType)
	case types.OCIImageIndex, types.DockerManifestList:
		// These are expected.
	default:
		// We could just return an error here, but some registries (e.g. static
		// registries) don't set the Content-Type headers correctly, so instead...
		logs.Warn.Printf("Unexpected media type for ImageIndex(): %s", d.MediaType)
	}
	return d.remoteIndex(), nil
}

func (d *Descriptor) remoteImage() *remoteImage {
	return &remoteImage{
		fetcher:    d.fetcher,
		manifest:   d.Manifest,
		mediaType:  d.MediaType,
		descriptor: &d.Descriptor,
	}
}

func (d *Descriptor) remoteIndex() *remoteIndex {
	return &remoteIndex{
		fetcher:    d.fetcher,
		manifest:   d.Manifest,
		mediaType:  d.MediaType,
		descriptor: &d.Descriptor,
	}
}

// fetcher implements methods for reading from a registry.
type fetcher struct {
	Ref     name.Reference
	Client  *http.Client
	context context.Context
}

func makeFetcher(ref name.Reference, o *options) (*fetcher, error) {
	tr, err := transport.NewWithContext(o.context, ref.Context().Registry, o.auth, o.transport, []string{ref.Scope(transport.PullScope)})
	if err != nil {
		return nil, err
	}
	return &fetcher{
		Ref:     ref,
		Client:  &http.Client{Transport: tr},
		context: o.context,
	}, nil
}

// url returns a url.Url for the specified path in the context of this remote image reference.
func (f *fetcher) url(resource, identifier string) url.URL {
	return url.URL{
		Scheme: f.Ref.Context().Registry.Scheme(),
		Host:   f.Ref.Context().RegistryStr(),
		Path:   fmt.Sprintf("/v2/%s/%s/%s", f.Ref.Context().RepositoryStr(), resource, identifier),
	}
}

func (f *fetcher) fetchManifest(ref name.Reference, acceptable []types.MediaType) ([]byte, *v1.Descriptor, error) {
	u := f.url("manifests", ref.Identifier())
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	accept := []string{}
	for _, mt := range acceptable {
		accept = append(accept, string(mt))
	}
	req.Header.Set("Accept", strings.Join(accept, ","))

	resp, err := f.Client.Do(req.WithContext(f.context))
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if err := transport.CheckError(resp, http.StatusOK); err != nil {
		return nil, nil, err
	}

	manifest, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	digest, size, err := v1.SHA256(bytes.NewReader(manifest))
	if err != nil {
		return nil, nil, err
	}

	mediaType := types.MediaType(resp.Header.Get("Content-Type"))
	contentDigest, err := v1.NewHash(resp.Header.Get("Docker-Content-Digest"))
	if err == nil && mediaType == types.DockerManifestSchema1Signed {
		// If we can parse the digest from the header, and it's a signed schema 1
		// manifest, let's use that for the digest to appease older registries.
		digest = contentDigest
	}

	// Validate the digest matches what we asked for, if pulling by digest.
	if dgst, ok := ref.(name.Digest); ok {
		if digest.String() != dgst.DigestStr() {
			return nil, nil, fmt.Errorf("manifest digest: %q does not match requested digest: %q for %q", digest, dgst.DigestStr(), f.Ref)
		}
	}
	// Do nothing for tags; I give up.
	//
	// We'd like to validate that the "Docker-Content-Digest" header matches what is returned by the registry,
	// but so many registries implement this incorrectly that it's not worth checking.
	//
	// For reference:
	// https://github.com/GoogleContainerTools/kaniko/issues/298

	// Return all this info since we have to calculate it anyway.
	desc := v1.Descriptor{
		Digest:    digest,
		Size:      size,
		MediaType: mediaType,
	}

	return manifest, &desc, nil
}

func (f *fetcher) headManifest(ref name.Reference, acceptable []types.MediaType) (*v1.Descriptor, error) {
	u := f.url("manifests", ref.Identifier())
	req, err := http.NewRequest(http.MethodHead, u.String(), nil)
	if err != nil {
		return nil, err
	}
	accept := []string{}
	for _, mt := range acceptable {
		accept = append(accept, string(mt))
	}
	req.Header.Set("Accept", strings.Join(accept, ","))

	resp, err := f.Client.Do(req.WithContext(f.context))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := transport.CheckError(resp, http.StatusOK); err != nil {
		return nil, err
	}

	mth := resp.Header.Get("Content-Type")
	if mth == "" {
		return nil, fmt.Errorf("HEAD %s: response did not include Content-Type header", u.String())
	}
	mediaType := types.MediaType(mth)

	size := resp.ContentLength
	if size == -1 {
		return nil, fmt.Errorf("GET %s: response did not include Content-Length header", u.String())
	}

	dh := resp.Header.Get("Docker-Content-Digest")
	if dh == "" {
		return nil, fmt.Errorf("HEAD %s: response did not include Docker-Content-Digest header", u.String())
	}
	digest, err := v1.NewHash(dh)
	if err != nil {
		return nil, err
	}

	// Validate the digest matches what we asked for, if pulling by digest.
	if dgst, ok := ref.(name.Digest); ok {
		if digest.String() != dgst.DigestStr() {
			return nil, fmt.Errorf("manifest digest: %q does not match requested digest: %q for %q", digest, dgst.DigestStr(), f.Ref)
		}
	}

	// Return all this info since we have to calculate it anyway.
	return &v1.Descriptor{
		Digest:    digest,
		Size:      size,
		MediaType: mediaType,
	}, nil
}

func (f *fetcher) fetchBlob(ctx context.Context, size int64, h v1.Hash) (io.ReadCloser, error) {
	u := f.url("blobs", h.String())
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.Client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	if err := transport.CheckError(resp, http.StatusOK); err != nil {
		resp.Body.Close()
		return nil, err
	}

	// Do whatever we can.
	// If we have an expected size and Content-Length doesn't match, return an error.
	// If we don't have an expected size and we do have a Content-Length, use Content-Length.
	if hsize := resp.ContentLength; hsize != -1 {
		if size == verify.SizeUnknown {
			size = hsize
		} else if hsize != size {
			return nil, fmt.Errorf("GET %s: Content-Length header %d does not match expected size %d", u.String(), hsize, size)
		}
	}

	return verify.ReadCloser(resp.Body, size, h)
}

func (f *fetcher) headBlob(h v1.Hash) (*http.Response, error) {
	u := f.url("blobs", h.String())
	req, err := http.NewRequest(http.MethodHead, u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.Client.Do(req.WithContext(f.context))
	if err != nil {
		return nil, err
	}

	if err := transport.CheckError(resp, http.StatusOK); err != nil {
		resp.Body.Close()
		return nil, err
	}

	return resp, nil
}

func (f *fetcher) blobExists(h v1.Hash) (bool, error) {
	u := f.url("blobs", h.String())
	req, err := http.NewRequest(http.MethodHead, u.String(), nil)
	if err != nil {
		return false, err
	}

	resp, err := f.Client.Do(req.WithContext(f.context))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if err := transport.CheckError(resp, http.StatusOK, http.StatusNotFound); err != nil {
		return false, err
	}

	return resp.StatusCode == http.StatusOK, nil
}
