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

package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	authchallenge "github.com/docker/distribution/registry/client/auth/challenge"
	"github.com/google/go-containerregistry/pkg/name"
)

type challenge string

const (
	anonymous challenge = "anonymous"
	basic     challenge = "basic"
	bearer    challenge = "bearer"
)

type pingResp struct {
	challenge challenge

	// Following the challenge there are often key/value pairs
	// e.g. Bearer service="gcr.io",realm="https://auth.gcr.io/v36/tokenz"
	parameters map[string]string

	// The registry's scheme to use. Communicates whether we fell back to http.
	scheme string
}

func (c challenge) Canonical() challenge {
	return challenge(strings.ToLower(string(c)))
}

func parseChallenge(suffix string) map[string]string {
	kv := make(map[string]string)
	for _, token := range strings.Split(suffix, ",") {
		// Trim any whitespace around each token.
		token = strings.Trim(token, " ")

		// Break the token into a key/value pair
		if parts := strings.SplitN(token, "=", 2); len(parts) == 2 {
			// Unquote the value, if it is quoted.
			kv[parts[0]] = strings.Trim(parts[1], `"`)
		} else {
			// If there was only one part, treat is as a key with an empty value
			kv[token] = ""
		}
	}
	return kv
}

func ping(ctx context.Context, reg name.Registry, t http.RoundTripper) (*pingResp, error) {
	client := http.Client{Transport: t}

	// This first attempts to use "https" for every request, falling back to http
	// if the registry matches our localhost heuristic or if it is intentionally
	// set to insecure via name.NewInsecureRegistry.
	schemes := []string{"https"}
	if reg.Scheme() == "http" {
		schemes = append(schemes, "http")
	}

	var errs []string
	for _, scheme := range schemes {
		url := fmt.Sprintf("%s://%s/v2/", scheme, reg.Name())
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req.WithContext(ctx))
		if err != nil {
			errs = append(errs, err.Error())
			// Potentially retry with http.
			continue
		}
		defer func() {
			// By draining the body, make sure to reuse the connection made by
			// the ping for the following access to the registry
			io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()
		}()

		switch resp.StatusCode {
		case http.StatusOK:
			// If we get a 200, then no authentication is needed.
			return &pingResp{
				challenge: anonymous,
				scheme:    scheme,
			}, nil
		case http.StatusUnauthorized:
			if challenges := authchallenge.ResponseChallenges(resp); len(challenges) != 0 {
				// If we hit more than one, let's try to find one that we know how to handle.
				wac := pickFromMultipleChallenges(challenges)
				return &pingResp{
					challenge:  challenge(wac.Scheme).Canonical(),
					parameters: wac.Parameters,
					scheme:     scheme,
				}, nil
			}
			// Otherwise, just return the challenge without parameters.
			return &pingResp{
				challenge: challenge(resp.Header.Get("WWW-Authenticate")).Canonical(),
				scheme:    scheme,
			}, nil
		default:
			return nil, CheckError(resp, http.StatusOK, http.StatusUnauthorized)
		}
	}
	return nil, errors.New(strings.Join(errs, "; "))
}

func pickFromMultipleChallenges(challenges []authchallenge.Challenge) authchallenge.Challenge {
	// It might happen there are multiple www-authenticate headers, e.g. `Negotiate` and `Basic`.
	// Picking simply the first one could result eventually in `unrecognized challenge` error,
	// that's why we're looping through the challenges in search for one that can be handled.
	allowedSchemes := []string{"basic", "bearer"}

	for _, wac := range challenges {
		currentScheme := strings.ToLower(wac.Scheme)
		for _, allowed := range allowedSchemes {
			if allowed == currentScheme {
				return wac
			}
		}
	}

	return challenges[0]
}
