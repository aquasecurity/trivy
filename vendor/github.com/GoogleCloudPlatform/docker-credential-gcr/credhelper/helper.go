// Copyright 2016 Google, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Package credhelper implements a Docker credential helper with special facilities
for GCR authentication.
*/
package credhelper

import (
	"errors"
	"fmt"
	"strings"

	"github.com/GoogleCloudPlatform/docker-credential-gcr/config"
	"github.com/GoogleCloudPlatform/docker-credential-gcr/store"
	"github.com/GoogleCloudPlatform/docker-credential-gcr/util/cmd"
	"github.com/docker/docker-credential-helpers/credentials"

	"golang.org/x/oauth2/google"
)

// gcrCredHelper implements a credentials.Helper interface backed by a GCR
// credential store.
type gcrCredHelper struct {
	store   store.GCRCredStore
	userCfg config.UserConfig

	// helper methods, package exposed for testing
	envToken       func() (string, error)
	gcloudSDKToken func(cmd.Command) (string, error)
	credStoreToken func(store.GCRCredStore) (string, error)

	// `gcloud` exec interface, package exposed for testing
	gcloudCmd cmd.Command
}

// NewGCRCredentialHelper returns a Docker credential helper which
// specializes in GCR's authentication schemes.
func NewGCRCredentialHelper(store store.GCRCredStore, userCfg config.UserConfig) credentials.Helper {
	return &gcrCredHelper{
		store:          store,
		userCfg:        userCfg,
		credStoreToken: tokenFromPrivateStore,
		gcloudSDKToken: tokenFromGcloudSDK,
		envToken:       tokenFromEnv,
		gcloudCmd:      &cmd.RealImpl{Command: "gcloud"},
	}
}

// Delete lists all stored credentials and associated usernames.
func (*gcrCredHelper) List() (map[string]string, error) {
	return nil, errors.New("list is unimplemented")
}

// Add adds new third-party credentials to the keychain.
func (*gcrCredHelper) Add(*credentials.Credentials) error {
	return errors.New("add is unimplemented")
}

// Delete removes third-party credentials from the store.
func (*gcrCredHelper) Delete(string) error {
	return errors.New("delete is unimplemented")
}

// Get returns the username and secret to use for a given registry server URL.
func (ch *gcrCredHelper) Get(serverURL string) (string, string, error) {
	return ch.gcrCreds()
}

func (ch *gcrCredHelper) gcrCreds() (string, string, error) {
	accessToken, err := ch.getGCRAccessToken()
	if err != nil {
		return "", "", helperErr("could not retrieve GCR's access token", err)
	}
	return config.GcrOAuth2Username, accessToken, nil
}

// getGCRAccessToken attempts to retrieve a GCR access token from the sources
// listed by ch.tokenSources, in order.
func (ch *gcrCredHelper) getGCRAccessToken() (string, error) {
	var token string
	var err error
	tokenSources := ch.userCfg.TokenSources()
	for _, source := range tokenSources {
		switch source {
		case "env":
			token, err = ch.envToken()
		case "gcloud", "gcloud_sdk": // gcloud_sdk supported for legacy reasons
			token, err = ch.gcloudSDKToken(ch.gcloudCmd)
		case "store":
			token, err = ch.credStoreToken(ch.store)
		default:
			return "", helperErr("unknown token source: "+source, nil)
		}

		// if we successfully retrieved a token, break.
		if err == nil {
			break
		}
	}

	return token, err
}

/*
	tokenFromEnv retrieves a gcloud access_token from the environment.

	From https://godoc.org/golang.org/x/oauth2/google:

	DefaultTokenSource is a token source that uses "Application Default Credentials".

	It looks for credentials in the following places, preferring the first location found:

	1. A JSON file whose path is specified by the
	   GOOGLE_APPLICATION_CREDENTIALS environment variable.
	2. A JSON file in a location known to the gcloud command-line tool.
	   On Windows, this is %APPDATA%/gcloud/application_default_credentials.json.
	   On other systems, $HOME/.config/gcloud/application_default_credentials.json.
	3. On Google App Engine it uses the appengine.AccessToken function.
	4. On Google Compute Engine and Google App Engine Managed VMs, it fetches
	   credentials from the metadata server.
	   (In this final case any provided scopes are ignored.)
*/
func tokenFromEnv() (string, error) {
	ts, err := google.DefaultTokenSource(config.OAuthHTTPContext, config.GCRScopes...)
	if err != nil {
		return "", err
	}

	token, err := ts.Token()
	if err != nil {
		return "", err
	}

	if !token.Valid() {
		return "", helperErr("token was invalid", nil)
	}

	if token.Type() != "Bearer" {
		return "", helperErr(fmt.Sprintf("expected token type \"Bearer\" but got \"%s\"", token.Type()), nil)
	}

	return token.AccessToken, nil
}

// tokenFromGcloudSDK attempts to generate an access_token using the gcloud SDK.
func tokenFromGcloudSDK(gcloudCmd cmd.Command) (string, error) {
	// shelling out to gcloud is the only currently supported way of
	// obtaining the gcloud access_token
	stdout, err := gcloudCmd.Exec("config", "config-helper", "--force-auth-refresh", "--format=value(credential.access_token)")
	if err != nil {
		return "", helperErr("`gcloud config config-helper` failed", err)
	}

	token := strings.TrimSpace(string(stdout))
	if token == "" {
		return "", helperErr("`gcloud config config-helper` returned an empty access_token", nil)
	}
	return token, nil
}

func tokenFromPrivateStore(store store.GCRCredStore) (string, error) {
	gcrAuth, err := store.GetGCRAuth()
	if err != nil {
		return "", err
	}
	ts := gcrAuth.TokenSource(config.OAuthHTTPContext)
	tok, err := ts.Token()
	if err != nil {
		return "", err
	}
	if !tok.Valid() {
		return "", helperErr("token was invalid", nil)
	}

	return tok.AccessToken, nil
}

func helperErr(message string, err error) error {
	if err == nil {
		return fmt.Errorf("docker-credential-gcr/helper: %s", message)
	}
	return fmt.Errorf("docker-credential-gcr/helper: %s: %v", message, err)
}
