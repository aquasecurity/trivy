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
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// Delete removes the specified image reference from the remote registry.
func Delete(ref name.Reference, options ...Option) error {
	o, err := makeOptions(ref.Context(), options...)
	if err != nil {
		return err
	}
	scopes := []string{ref.Scope(transport.DeleteScope)}
	tr, err := transport.NewWithContext(o.context, ref.Context().Registry, o.auth, o.transport, scopes)
	if err != nil {
		return err
	}
	c := &http.Client{Transport: tr}

	u := url.URL{
		Scheme: ref.Context().Registry.Scheme(),
		Host:   ref.Context().RegistryStr(),
		Path:   fmt.Sprintf("/v2/%s/manifests/%s", ref.Context().RepositoryStr(), ref.Identifier()),
	}

	req, err := http.NewRequest(http.MethodDelete, u.String(), nil)
	if err != nil {
		return err
	}

	resp, err := c.Do(req.WithContext(o.context))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return transport.CheckError(resp, http.StatusOK, http.StatusAccepted)
}
