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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

type catalog struct {
	Repos []string `json:"repositories"`
}

// CatalogPage calls /_catalog, returning the list of repositories on the registry.
func CatalogPage(target name.Registry, last string, n int, options ...Option) ([]string, error) {
	o, err := makeOptions(target, options...)
	if err != nil {
		return nil, err
	}

	scopes := []string{target.Scope(transport.PullScope)}
	tr, err := transport.NewWithContext(o.context, target, o.auth, o.transport, scopes)
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf("last=%s&n=%d", url.QueryEscape(last), n)

	uri := url.URL{
		Scheme:   target.Scheme(),
		Host:     target.RegistryStr(),
		Path:     "/v2/_catalog",
		RawQuery: query,
	}

	client := http.Client{Transport: tr}
	req, err := http.NewRequest(http.MethodGet, uri.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req.WithContext(o.context))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := transport.CheckError(resp, http.StatusOK); err != nil {
		return nil, err
	}

	var parsed catalog
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}

	return parsed.Repos, nil
}

// Catalog calls /_catalog, returning the list of repositories on the registry.
func Catalog(ctx context.Context, target name.Registry, options ...Option) ([]string, error) {
	o, err := makeOptions(target, options...)
	if err != nil {
		return nil, err
	}

	scopes := []string{target.Scope(transport.PullScope)}
	tr, err := transport.NewWithContext(o.context, target, o.auth, o.transport, scopes)
	if err != nil {
		return nil, err
	}

	uri := &url.URL{
		Scheme: target.Scheme(),
		Host:   target.RegistryStr(),
		Path:   "/v2/_catalog",
	}

	if o.pageSize > 0 {
		uri.RawQuery = fmt.Sprintf("n=%d", o.pageSize)
	}

	client := http.Client{Transport: tr}

	// WithContext overrides the ctx passed directly.
	if o.context != context.Background() {
		ctx = o.context
	}

	var (
		parsed   catalog
		repoList []string
	)

	// get responses until there is no next page
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		req, err := http.NewRequest("GET", uri.String(), nil)
		if err != nil {
			return nil, err
		}
		req = req.WithContext(ctx)

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		if err := transport.CheckError(resp, http.StatusOK); err != nil {
			return nil, err
		}

		if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
			return nil, err
		}
		if err := resp.Body.Close(); err != nil {
			return nil, err
		}

		repoList = append(repoList, parsed.Repos...)

		uri, err = getNextPageURL(resp)
		if err != nil {
			return nil, err
		}
		// no next page
		if uri == nil {
			break
		}
	}
	return repoList, nil
}
