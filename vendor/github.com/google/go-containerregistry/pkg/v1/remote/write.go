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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/google/go-containerregistry/internal/redact"
	"github.com/google/go-containerregistry/internal/retry"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/stream"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"golang.org/x/sync/errgroup"
)

// Taggable is an interface that enables a manifest PUT (e.g. for tagging).
type Taggable interface {
	RawManifest() ([]byte, error)
}

// Write pushes the provided img to the specified image reference.
func Write(ref name.Reference, img v1.Image, options ...Option) (rerr error) {
	o, err := makeOptions(ref.Context(), options...)
	if err != nil {
		return err
	}

	var lastUpdate *v1.Update
	if o.updates != nil {
		lastUpdate = &v1.Update{}
		lastUpdate.Total, err = countImage(img, o.allowNondistributableArtifacts)
		if err != nil {
			return err
		}
		defer close(o.updates)
		defer func() { _ = sendError(o.updates, rerr) }()
	}
	return writeImage(o.context, ref, img, o, lastUpdate)
}

func writeImage(ctx context.Context, ref name.Reference, img v1.Image, o *options, lastUpdate *v1.Update) error {
	ls, err := img.Layers()
	if err != nil {
		return err
	}
	scopes := scopesForUploadingImage(ref.Context(), ls)
	tr, err := transport.NewWithContext(o.context, ref.Context().Registry, o.auth, o.transport, scopes)
	if err != nil {
		return err
	}
	w := writer{
		repo:       ref.Context(),
		client:     &http.Client{Transport: tr},
		context:    ctx,
		updates:    o.updates,
		lastUpdate: lastUpdate,
		backoff:    o.retryBackoff,
		predicate:  o.retryPredicate,
	}

	// Upload individual blobs and collect any errors.
	blobChan := make(chan v1.Layer, 2*o.jobs)
	g, gctx := errgroup.WithContext(ctx)
	for i := 0; i < o.jobs; i++ {
		// Start N workers consuming blobs to upload.
		g.Go(func() error {
			for b := range blobChan {
				if err := w.uploadOne(gctx, b); err != nil {
					return err
				}
			}
			return nil
		})
	}

	// Upload individual layers in goroutines and collect any errors.
	// If we can dedupe by the layer digest, try to do so. If we can't determine
	// the digest for whatever reason, we can't dedupe and might re-upload.
	g.Go(func() error {
		defer close(blobChan)
		uploaded := map[v1.Hash]bool{}
		for _, l := range ls {
			l := l

			// Handle foreign layers.
			mt, err := l.MediaType()
			if err != nil {
				return err
			}
			if !mt.IsDistributable() && !o.allowNondistributableArtifacts {
				continue
			}

			// Streaming layers calculate their digests while uploading them. Assume
			// an error here indicates we need to upload the layer.
			h, err := l.Digest()
			if err == nil {
				// If we can determine the layer's digest ahead of
				// time, use it to dedupe uploads.
				if uploaded[h] {
					continue // Already uploading.
				}
				uploaded[h] = true
			}
			select {
			case blobChan <- l:
			case <-gctx.Done():
				return gctx.Err()
			}
		}
		return nil
	})

	if l, err := partial.ConfigLayer(img); err != nil {
		// We can't read the ConfigLayer, possibly because of streaming layers,
		// since the layer DiffIDs haven't been calculated yet. Attempt to wait
		// for the other layers to be uploaded, then try the config again.
		if err := g.Wait(); err != nil {
			return err
		}

		// Now that all the layers are uploaded, try to upload the config file blob.
		l, err := partial.ConfigLayer(img)
		if err != nil {
			return err
		}
		if err := w.uploadOne(ctx, l); err != nil {
			return err
		}
	} else {
		// We *can* read the ConfigLayer, so upload it concurrently with the layers.
		g.Go(func() error {
			return w.uploadOne(gctx, l)
		})

		// Wait for the layers + config.
		if err := g.Wait(); err != nil {
			return err
		}
	}

	// With all of the constituent elements uploaded, upload the manifest
	// to commit the image.
	return w.commitManifest(ctx, img, ref)
}

// writer writes the elements of an image to a remote image reference.
type writer struct {
	repo    name.Repository
	client  *http.Client
	context context.Context

	updates    chan<- v1.Update
	lastUpdate *v1.Update
	backoff    Backoff
	predicate  retry.Predicate
}

func sendError(ch chan<- v1.Update, err error) error {
	if err != nil && ch != nil {
		ch <- v1.Update{Error: err}
	}
	return err
}

// url returns a url.Url for the specified path in the context of this remote image reference.
func (w *writer) url(path string) url.URL {
	return url.URL{
		Scheme: w.repo.Registry.Scheme(),
		Host:   w.repo.RegistryStr(),
		Path:   path,
	}
}

// nextLocation extracts the fully-qualified URL to which we should send the next request in an upload sequence.
func (w *writer) nextLocation(resp *http.Response) (string, error) {
	loc := resp.Header.Get("Location")
	if len(loc) == 0 {
		return "", errors.New("missing Location header")
	}
	u, err := url.Parse(loc)
	if err != nil {
		return "", err
	}

	// If the location header returned is just a url path, then fully qualify it.
	// We cannot simply call w.url, since there might be an embedded query string.
	return resp.Request.URL.ResolveReference(u).String(), nil
}

// checkExistingBlob checks if a blob exists already in the repository by making a
// HEAD request to the blob store API.  GCR performs an existence check on the
// initiation if "mount" is specified, even if no "from" sources are specified.
// However, this is not broadly applicable to all registries, e.g. ECR.
func (w *writer) checkExistingBlob(h v1.Hash) (bool, error) {
	u := w.url(fmt.Sprintf("/v2/%s/blobs/%s", w.repo.RepositoryStr(), h.String()))

	req, err := http.NewRequest(http.MethodHead, u.String(), nil)
	if err != nil {
		return false, err
	}

	resp, err := w.client.Do(req.WithContext(w.context))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if err := transport.CheckError(resp, http.StatusOK, http.StatusNotFound); err != nil {
		return false, err
	}

	return resp.StatusCode == http.StatusOK, nil
}

// checkExistingManifest checks if a manifest exists already in the repository
// by making a HEAD request to the manifest API.
func (w *writer) checkExistingManifest(h v1.Hash, mt types.MediaType) (bool, error) {
	u := w.url(fmt.Sprintf("/v2/%s/manifests/%s", w.repo.RepositoryStr(), h.String()))

	req, err := http.NewRequest(http.MethodHead, u.String(), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", string(mt))

	resp, err := w.client.Do(req.WithContext(w.context))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if err := transport.CheckError(resp, http.StatusOK, http.StatusNotFound); err != nil {
		return false, err
	}

	return resp.StatusCode == http.StatusOK, nil
}

// initiateUpload initiates the blob upload, which starts with a POST that can
// optionally include the hash of the layer and a list of repositories from
// which that layer might be read. On failure, an error is returned.
// On success, the layer was either mounted (nothing more to do) or a blob
// upload was initiated and the body of that blob should be sent to the returned
// location.
func (w *writer) initiateUpload(from, mount string) (location string, mounted bool, err error) {
	u := w.url(fmt.Sprintf("/v2/%s/blobs/uploads/", w.repo.RepositoryStr()))
	uv := url.Values{}
	if mount != "" && from != "" {
		// Quay will fail if we specify a "mount" without a "from".
		uv["mount"] = []string{mount}
		uv["from"] = []string{from}
	}
	u.RawQuery = uv.Encode()

	// Make the request to initiate the blob upload.
	req, err := http.NewRequest(http.MethodPost, u.String(), nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req.WithContext(w.context))
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	if err := transport.CheckError(resp, http.StatusCreated, http.StatusAccepted); err != nil {
		return "", false, err
	}

	// Check the response code to determine the result.
	switch resp.StatusCode {
	case http.StatusCreated:
		// We're done, we were able to fast-path.
		return "", true, nil
	case http.StatusAccepted:
		// Proceed to PATCH, upload has begun.
		loc, err := w.nextLocation(resp)
		return loc, false, err
	default:
		panic("Unreachable: initiateUpload")
	}
}

type progressReader struct {
	rc io.ReadCloser

	count      *int64 // number of bytes this reader has read, to support resetting on retry.
	updates    chan<- v1.Update
	lastUpdate *v1.Update
}

func (r *progressReader) Read(b []byte) (int, error) {
	n, err := r.rc.Read(b)
	if err != nil {
		return n, err
	}
	atomic.AddInt64(r.count, int64(n))
	// TODO: warn/debug log if sending takes too long, or if sending is blocked while context is cancelled.
	r.updates <- v1.Update{
		Total:    r.lastUpdate.Total,
		Complete: atomic.AddInt64(&r.lastUpdate.Complete, int64(n)),
	}
	return n, nil
}

func (r *progressReader) Close() error { return r.rc.Close() }

// streamBlob streams the contents of the blob to the specified location.
// On failure, this will return an error.  On success, this will return the location
// header indicating how to commit the streamed blob.
func (w *writer) streamBlob(ctx context.Context, blob io.ReadCloser, streamLocation string) (commitLocation string, rerr error) {
	reset := func() {}
	defer func() {
		if rerr != nil {
			reset()
		}
	}()
	if w.updates != nil {
		var count int64
		blob = &progressReader{rc: blob, updates: w.updates, lastUpdate: w.lastUpdate, count: &count}
		reset = func() {
			atomic.AddInt64(&w.lastUpdate.Complete, -count)
			w.updates <- *w.lastUpdate
		}
	}

	req, err := http.NewRequest(http.MethodPatch, streamLocation, blob)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := w.client.Do(req.WithContext(ctx))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if err := transport.CheckError(resp, http.StatusNoContent, http.StatusAccepted, http.StatusCreated); err != nil {
		return "", err
	}

	// The blob has been uploaded, return the location header indicating
	// how to commit this layer.
	return w.nextLocation(resp)
}

// commitBlob commits this blob by sending a PUT to the location returned from
// streaming the blob.
func (w *writer) commitBlob(location, digest string) error {
	u, err := url.Parse(location)
	if err != nil {
		return err
	}
	v := u.Query()
	v.Set("digest", digest)
	u.RawQuery = v.Encode()

	req, err := http.NewRequest(http.MethodPut, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := w.client.Do(req.WithContext(w.context))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return transport.CheckError(resp, http.StatusCreated)
}

// incrProgress increments and sends a progress update, if WithProgress is used.
func (w *writer) incrProgress(written int64) {
	if w.updates == nil {
		return
	}
	w.updates <- v1.Update{
		Total:    w.lastUpdate.Total,
		Complete: atomic.AddInt64(&w.lastUpdate.Complete, written),
	}
}

// uploadOne performs a complete upload of a single layer.
func (w *writer) uploadOne(ctx context.Context, l v1.Layer) error {
	var from, mount string
	if h, err := l.Digest(); err == nil {
		// If we know the digest, this isn't a streaming layer. Do an existence
		// check so we can skip uploading the layer if possible.
		existing, err := w.checkExistingBlob(h)
		if err != nil {
			return err
		}
		if existing {
			size, err := l.Size()
			if err != nil {
				return err
			}
			w.incrProgress(size)
			logs.Progress.Printf("existing blob: %v", h)
			return nil
		}

		mount = h.String()
	}
	if ml, ok := l.(*MountableLayer); ok {
		if w.repo.RegistryStr() == ml.Reference.Context().RegistryStr() {
			from = ml.Reference.Context().RepositoryStr()
		}
	}

	tryUpload := func() error {
		location, mounted, err := w.initiateUpload(from, mount)
		if err != nil {
			return err
		} else if mounted {
			size, err := l.Size()
			if err != nil {
				return err
			}
			w.incrProgress(size)
			h, err := l.Digest()
			if err != nil {
				return err
			}
			logs.Progress.Printf("mounted blob: %s", h.String())
			return nil
		}

		// Only log layers with +json or +yaml. We can let through other stuff if it becomes popular.
		// TODO(opencontainers/image-spec#791): Would be great to have an actual parser.
		mt, err := l.MediaType()
		if err != nil {
			return err
		}
		smt := string(mt)
		if !(strings.HasSuffix(smt, "+json") || strings.HasSuffix(smt, "+yaml")) {
			ctx = redact.NewContext(ctx, "omitting binary blobs from logs")
		}

		blob, err := l.Compressed()
		if err != nil {
			return err
		}
		location, err = w.streamBlob(ctx, blob, location)
		if err != nil {
			return err
		}

		h, err := l.Digest()
		if err != nil {
			return err
		}
		digest := h.String()

		if err := w.commitBlob(location, digest); err != nil {
			return err
		}
		logs.Progress.Printf("pushed blob: %s", digest)
		return nil
	}

	return retry.Retry(tryUpload, w.predicate, w.backoff)
}

type withLayer interface {
	Layer(v1.Hash) (v1.Layer, error)
}

func (w *writer) writeIndex(ctx context.Context, ref name.Reference, ii v1.ImageIndex, options ...Option) error {
	index, err := ii.IndexManifest()
	if err != nil {
		return err
	}

	o, err := makeOptions(ref.Context(), options...)
	if err != nil {
		return err
	}

	// TODO(#803): Pipe through remote.WithJobs and upload these in parallel.
	for _, desc := range index.Manifests {
		ref := ref.Context().Digest(desc.Digest.String())
		exists, err := w.checkExistingManifest(desc.Digest, desc.MediaType)
		if err != nil {
			return err
		}
		if exists {
			logs.Progress.Print("existing manifest: ", desc.Digest)
			continue
		}

		switch desc.MediaType {
		case types.OCIImageIndex, types.DockerManifestList:
			ii, err := ii.ImageIndex(desc.Digest)
			if err != nil {
				return err
			}
			if err := w.writeIndex(ctx, ref, ii, options...); err != nil {
				return err
			}
		case types.OCIManifestSchema1, types.DockerManifestSchema2:
			img, err := ii.Image(desc.Digest)
			if err != nil {
				return err
			}
			if err := writeImage(ctx, ref, img, o, w.lastUpdate); err != nil {
				return err
			}
		default:
			// Workaround for #819.
			if wl, ok := ii.(withLayer); ok {
				layer, err := wl.Layer(desc.Digest)
				if err != nil {
					return err
				}
				if err := w.uploadOne(ctx, layer); err != nil {
					return err
				}
			}
		}
	}

	// With all of the constituent elements uploaded, upload the manifest
	// to commit the image.
	return w.commitManifest(ctx, ii, ref)
}

type withMediaType interface {
	MediaType() (types.MediaType, error)
}

// This is really silly, but go interfaces don't let me satisfy remote.Taggable
// with remote.Descriptor because of name collisions between method names and
// struct fields.
//
// Use reflection to either pull the v1.Descriptor out of remote.Descriptor or
// create a descriptor based on the RawManifest and (optionally) MediaType.
func unpackTaggable(t Taggable) ([]byte, *v1.Descriptor, error) {
	if d, ok := t.(*Descriptor); ok {
		return d.Manifest, &d.Descriptor, nil
	}
	b, err := t.RawManifest()
	if err != nil {
		return nil, nil, err
	}

	// A reasonable default if Taggable doesn't implement MediaType.
	mt := types.DockerManifestSchema2

	if wmt, ok := t.(withMediaType); ok {
		m, err := wmt.MediaType()
		if err != nil {
			return nil, nil, err
		}
		mt = m
	}

	h, sz, err := v1.SHA256(bytes.NewReader(b))
	if err != nil {
		return nil, nil, err
	}

	return b, &v1.Descriptor{
		MediaType: mt,
		Size:      sz,
		Digest:    h,
	}, nil
}

// commitManifest does a PUT of the image's manifest.
func (w *writer) commitManifest(ctx context.Context, t Taggable, ref name.Reference) error {
	tryUpload := func() error {
		raw, desc, err := unpackTaggable(t)
		if err != nil {
			return err
		}

		u := w.url(fmt.Sprintf("/v2/%s/manifests/%s", w.repo.RepositoryStr(), ref.Identifier()))

		// Make the request to PUT the serialized manifest
		req, err := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(raw))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", string(desc.MediaType))

		resp, err := w.client.Do(req.WithContext(ctx))
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if err := transport.CheckError(resp, http.StatusOK, http.StatusCreated, http.StatusAccepted); err != nil {
			return err
		}

		// The image was successfully pushed!
		logs.Progress.Printf("%v: digest: %v size: %d", ref, desc.Digest, desc.Size)
		w.incrProgress(int64(len(raw)))
		return nil
	}

	return retry.Retry(tryUpload, w.predicate, w.backoff)
}

func scopesForUploadingImage(repo name.Repository, layers []v1.Layer) []string {
	// use a map as set to remove duplicates scope strings
	scopeSet := map[string]struct{}{}

	for _, l := range layers {
		if ml, ok := l.(*MountableLayer); ok {
			// we will add push scope for ref.Context() after the loop.
			// for now we ask pull scope for references of the same registry
			if ml.Reference.Context().String() != repo.String() && ml.Reference.Context().Registry.String() == repo.Registry.String() {
				scopeSet[ml.Reference.Scope(transport.PullScope)] = struct{}{}
			}
		}
	}

	scopes := make([]string, 0)
	// Push scope should be the first element because a few registries just look at the first scope to determine access.
	scopes = append(scopes, repo.Scope(transport.PushScope))

	for scope := range scopeSet {
		scopes = append(scopes, scope)
	}

	return scopes
}

// WriteIndex pushes the provided ImageIndex to the specified image reference.
// WriteIndex will attempt to push all of the referenced manifests before
// attempting to push the ImageIndex, to retain referential integrity.
func WriteIndex(ref name.Reference, ii v1.ImageIndex, options ...Option) (rerr error) {
	o, err := makeOptions(ref.Context(), options...)
	if err != nil {
		return err
	}

	scopes := []string{ref.Scope(transport.PushScope)}
	tr, err := transport.NewWithContext(o.context, ref.Context().Registry, o.auth, o.transport, scopes)
	if err != nil {
		return err
	}
	w := writer{
		repo:      ref.Context(),
		client:    &http.Client{Transport: tr},
		context:   o.context,
		updates:   o.updates,
		backoff:   o.retryBackoff,
		predicate: o.retryPredicate,
	}

	if o.updates != nil {
		w.lastUpdate = &v1.Update{}
		w.lastUpdate.Total, err = countIndex(ii, o.allowNondistributableArtifacts)
		if err != nil {
			return err
		}
		defer close(o.updates)
		defer func() { sendError(o.updates, rerr) }()
	}

	return w.writeIndex(o.context, ref, ii, options...)
}

// countImage counts the total size of all layers + config blob + manifest for
// an image. It de-dupes duplicate layers.
func countImage(img v1.Image, allowNondistributableArtifacts bool) (int64, error) {
	var total int64
	ls, err := img.Layers()
	if err != nil {
		return 0, err
	}
	seen := map[v1.Hash]bool{}
	for _, l := range ls {
		// Handle foreign layers.
		mt, err := l.MediaType()
		if err != nil {
			return 0, err
		}
		if !mt.IsDistributable() && !allowNondistributableArtifacts {
			continue
		}

		// TODO: support streaming layers which update the total count as they write.
		if _, ok := l.(*stream.Layer); ok {
			return 0, errors.New("cannot use stream.Layer and WithProgress")
		}

		// Dedupe layers.
		d, err := l.Digest()
		if err != nil {
			return 0, err
		}
		if seen[d] {
			continue
		}
		seen[d] = true

		size, err := l.Size()
		if err != nil {
			return 0, err
		}
		total += size
	}
	b, err := img.RawConfigFile()
	if err != nil {
		return 0, err
	}
	total += int64(len(b))
	size, err := img.Size()
	if err != nil {
		return 0, err
	}
	total += size
	return total, nil
}

// countIndex counts the total size of all images + sub-indexes for an index.
// It does not attempt to de-dupe duplicate images, etc.
func countIndex(idx v1.ImageIndex, allowNondistributableArtifacts bool) (int64, error) {
	var total int64
	mf, err := idx.IndexManifest()
	if err != nil {
		return 0, err
	}

	for _, desc := range mf.Manifests {
		switch desc.MediaType {
		case types.OCIImageIndex, types.DockerManifestList:
			sidx, err := idx.ImageIndex(desc.Digest)
			if err != nil {
				return 0, err
			}
			size, err := countIndex(sidx, allowNondistributableArtifacts)
			if err != nil {
				return 0, err
			}
			total += size
		case types.OCIManifestSchema1, types.DockerManifestSchema2:
			simg, err := idx.Image(desc.Digest)
			if err != nil {
				return 0, err
			}
			size, err := countImage(simg, allowNondistributableArtifacts)
			if err != nil {
				return 0, err
			}
			total += size
		default:
			// Workaround for #819.
			if wl, ok := idx.(withLayer); ok {
				layer, err := wl.Layer(desc.Digest)
				if err != nil {
					return 0, err
				}
				size, err := layer.Size()
				if err != nil {
					return 0, err
				}
				total += size
			}
		}
	}

	size, err := idx.Size()
	if err != nil {
		return 0, err
	}
	total += size
	return total, nil
}

// WriteLayer uploads the provided Layer to the specified repo.
func WriteLayer(repo name.Repository, layer v1.Layer, options ...Option) (rerr error) {
	o, err := makeOptions(repo, options...)
	if err != nil {
		return err
	}
	scopes := scopesForUploadingImage(repo, []v1.Layer{layer})
	tr, err := transport.NewWithContext(o.context, repo.Registry, o.auth, o.transport, scopes)
	if err != nil {
		return err
	}
	w := writer{
		repo:      repo,
		client:    &http.Client{Transport: tr},
		context:   o.context,
		updates:   o.updates,
		backoff:   o.retryBackoff,
		predicate: o.retryPredicate,
	}

	if o.updates != nil {
		defer close(o.updates)
		defer func() { sendError(o.updates, rerr) }()

		// TODO: support streaming layers which update the total count as they write.
		if _, ok := layer.(*stream.Layer); ok {
			return errors.New("cannot use stream.Layer and WithProgress")
		}
		size, err := layer.Size()
		if err != nil {
			return err
		}
		w.lastUpdate = &v1.Update{Total: size}
	}
	return w.uploadOne(o.context, layer)
}

// Tag adds a tag to the given Taggable via PUT /v2/.../manifests/<tag>
//
// Notable implementations of Taggable are v1.Image, v1.ImageIndex, and
// remote.Descriptor.
//
// If t implements MediaType, we will use that for the Content-Type, otherwise
// we will default to types.DockerManifestSchema2.
//
// Tag does not attempt to write anything other than the manifest, so callers
// should ensure that all blobs or manifests that are referenced by t exist
// in the target registry.
func Tag(tag name.Tag, t Taggable, options ...Option) error {
	return Put(tag, t, options...)
}

// Put adds a manifest from the given Taggable via PUT /v1/.../manifest/<ref>
//
// Notable implementations of Taggable are v1.Image, v1.ImageIndex, and
// remote.Descriptor.
//
// If t implements MediaType, we will use that for the Content-Type, otherwise
// we will default to types.DockerManifestSchema2.
//
// Put does not attempt to write anything other than the manifest, so callers
// should ensure that all blobs or manifests that are referenced by t exist
// in the target registry.
func Put(ref name.Reference, t Taggable, options ...Option) error {
	o, err := makeOptions(ref.Context(), options...)
	if err != nil {
		return err
	}
	scopes := []string{ref.Scope(transport.PushScope)}

	// TODO: This *always* does a token exchange. For some registries,
	// that's pretty slow. Some ideas;
	// * Tag could take a list of tags.
	// * Allow callers to pass in a transport.Transport, typecheck
	//   it to allow them to reuse the transport across multiple calls.
	// * WithTag option to do multiple manifest PUTs in commitManifest.
	tr, err := transport.NewWithContext(o.context, ref.Context().Registry, o.auth, o.transport, scopes)
	if err != nil {
		return err
	}
	w := writer{
		repo:      ref.Context(),
		client:    &http.Client{Transport: tr},
		context:   o.context,
		backoff:   o.retryBackoff,
		predicate: o.retryPredicate,
	}

	return w.commitManifest(o.context, t, ref)
}
