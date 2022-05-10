package remote

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// CheckPushPermission returns an error if the given keychain cannot authorize
// a push operation to the given ref.
//
// This can be useful to check whether the caller has permission to push an
// image before doing work to construct the image.
//
// TODO(#412): Remove the need for this method.
func CheckPushPermission(ref name.Reference, kc authn.Keychain, t http.RoundTripper) error {
	auth, err := kc.Resolve(ref.Context().Registry)
	if err != nil {
		return fmt.Errorf("resolving authorization for %v failed: %w", ref.Context().Registry, err)
	}

	scopes := []string{ref.Scope(transport.PushScope)}
	tr, err := transport.New(ref.Context().Registry, auth, t, scopes)
	if err != nil {
		return fmt.Errorf("creating push check transport for %v failed: %w", ref.Context().Registry, err)
	}
	// TODO(jasonhall): Against GCR, just doing the token handshake is
	// enough, but this doesn't extend to Dockerhub
	// (https://github.com/docker/hub-feedback/issues/1771), so we actually
	// need to initiate an upload to tell whether the credentials can
	// authorize a push. Figure out how to return early here when we can,
	// to avoid a roundtrip for spec-compliant registries.
	w := writer{
		repo:    ref.Context(),
		client:  &http.Client{Transport: tr},
		context: context.Background(),
	}
	loc, _, err := w.initiateUpload("", "")
	if loc != "" {
		// Since we're only initiating the upload to check whether we
		// can, we should attempt to cancel it, in case initiating
		// reserves some resources on the server. We shouldn't wait for
		// cancelling to complete, and we don't care if it fails.
		go w.cancelUpload(loc)
	}
	return err
}

func (w *writer) cancelUpload(loc string) {
	req, err := http.NewRequest(http.MethodDelete, loc, nil)
	if err != nil {
		return
	}
	_, _ = w.client.Do(req)
}
