// Copyright 2019 Google LLC All Rights Reserved.
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
	"io"

	"github.com/google/go-containerregistry/internal/redact"
	"github.com/google/go-containerregistry/internal/verify"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// remoteImagelayer implements partial.CompressedLayer
type remoteLayer struct {
	fetcher
	digest v1.Hash
}

// Compressed implements partial.CompressedLayer
func (rl *remoteLayer) Compressed() (io.ReadCloser, error) {
	// We don't want to log binary layers -- this can break terminals.
	ctx := redact.NewContext(rl.context, "omitting binary blobs from logs")
	return rl.fetchBlob(ctx, verify.SizeUnknown, rl.digest)
}

// Compressed implements partial.CompressedLayer
func (rl *remoteLayer) Size() (int64, error) {
	resp, err := rl.headBlob(rl.digest)
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()
	return resp.ContentLength, nil
}

// Digest implements partial.CompressedLayer
func (rl *remoteLayer) Digest() (v1.Hash, error) {
	return rl.digest, nil
}

// MediaType implements v1.Layer
func (rl *remoteLayer) MediaType() (types.MediaType, error) {
	return types.DockerLayer, nil
}

// See partial.Exists.
func (rl *remoteLayer) Exists() (bool, error) {
	return rl.blobExists(rl.digest)
}

// Layer reads the given blob reference from a registry as a Layer. A blob
// reference here is just a punned name.Digest where the digest portion is the
// digest of the blob to be read and the repository portion is the repo where
// that blob lives.
func Layer(ref name.Digest, options ...Option) (v1.Layer, error) {
	o, err := makeOptions(ref.Context(), options...)
	if err != nil {
		return nil, err
	}
	f, err := makeFetcher(ref, o)
	if err != nil {
		return nil, err
	}
	h, err := v1.NewHash(ref.Identifier())
	if err != nil {
		return nil, err
	}
	l, err := partial.CompressedToLayer(&remoteLayer{
		fetcher: *f,
		digest:  h,
	})
	if err != nil {
		return nil, err
	}
	return &MountableLayer{
		Layer:     l,
		Reference: ref,
	}, nil
}
