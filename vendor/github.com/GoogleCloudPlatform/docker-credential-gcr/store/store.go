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
Package store implements a credential store that is capable of storing both
plain Docker credentials as well as GCR access and refresh tokens.
*/
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"context"

	"github.com/GoogleCloudPlatform/docker-credential-gcr/config"
	"github.com/GoogleCloudPlatform/docker-credential-gcr/util"
	"github.com/docker/docker-credential-helpers/credentials"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	credentialStoreEnvVar   = "DOCKER_CREDENTIAL_GCR_STORE"
	credentialStoreFilename = "docker_credentials.json"
)

type tokens struct {
	AccessToken  string     `json:"access_token"`
	RefreshToken string     `json:"refresh_token"`
	TokenExpiry  *time.Time `json:"token_expiry"`
}

type dockerCredentials struct {
	GCRCreds *tokens `json:"gcrCreds,omitempty"`
}

// A GCRAuth provides access to tokens from a prior login.
type GCRAuth struct {
	conf         *oauth2.Config
	initialToken *oauth2.Token
}

// TokenSource returns an oauth2.TokenSource that retrieve tokens from
// GCR credentials using the provided context.
// It will returns the current access token stored in the credentials,
// and refresh it when it expires, but it won't update the credentials
// with the new access token.
func (a *GCRAuth) TokenSource(ctx context.Context) oauth2.TokenSource {
	return a.conf.TokenSource(ctx, a.initialToken)
}

// GCRCredStore describes the interface for a store capable of storing both
// GCR's credentials (OAuth2 access/refresh tokens) as well as generic
// Docker credentials.
type GCRCredStore interface {
	GetGCRAuth() (*GCRAuth, error)
	SetGCRAuth(tok *oauth2.Token) error
	DeleteGCRAuth() error
}

type credStore struct {
	credentialPath string
}

// DefaultGCRCredStore returns a GCRCredStore which is backed by a file.
func DefaultGCRCredStore() (GCRCredStore, error) {
	path, err := dockerCredentialPath()
	return &credStore{
		credentialPath: path,
	}, err
}

// NewGCRCredStore returns a GCRCredStore which is backed by the given file.
func NewGCRCredStore(path string) GCRCredStore {
	return &credStore{
		credentialPath: path,
	}
}

// GetGCRAuth creates an GCRAuth for the currently signed-in account.
func (s *credStore) GetGCRAuth() (*GCRAuth, error) {
	creds, err := s.loadDockerCredentials()
	if err != nil {
		if os.IsNotExist(err) {
			// No file, no credentials.
			return nil, credentials.NewErrCredentialsNotFound()
		}
		return nil, err
	}

	if creds.GCRCreds == nil {
		return nil, errors.New("GCR Credentials not present in store")
	}

	var expiry time.Time
	if creds.GCRCreds.TokenExpiry != nil {
		expiry = *creds.GCRCreds.TokenExpiry
	}

	return &GCRAuth{
		conf: &oauth2.Config{
			ClientID:     config.GCRCredHelperClientID,
			ClientSecret: config.GCRCredHelperClientNotSoSecret,
			Scopes:       config.GCRScopes,
			Endpoint:     google.Endpoint,
			RedirectURL:  "oob",
		},
		initialToken: &oauth2.Token{
			AccessToken:  creds.GCRCreds.AccessToken,
			RefreshToken: creds.GCRCreds.RefreshToken,
			Expiry:       expiry,
		},
	}, nil
}

// SetGCRAuth sets the stored GCR credentials.
func (s *credStore) SetGCRAuth(tok *oauth2.Token) error {
	creds, err := s.loadDockerCredentials()
	if err != nil {
		// It's OK if we couldn't read any credentials,
		// making a new file.
		creds = &dockerCredentials{}
	}

	creds.GCRCreds = &tokens{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		TokenExpiry:  &tok.Expiry,
	}

	return s.setDockerCredentials(creds)
}

// DeleteGCRAuth deletes the stored GCR credentials.
func (s *credStore) DeleteGCRAuth() error {
	creds, err := s.loadDockerCredentials()
	if err != nil {
		if os.IsNotExist(err) {
			// No file, no credentials.
			return nil
		}
		return err
	}

	// Optimization: only perform a 'set' if necessary
	if creds.GCRCreds != nil {
		creds.GCRCreds = nil
		return s.setDockerCredentials(creds)
	}
	return nil
}

func (s *credStore) createCredentialFile() (*os.File, error) {
	// create the gcloud config dir, if it doesnt exist
	if err := os.MkdirAll(filepath.Dir(s.credentialPath), 0777); err != nil {
		return nil, err
	}
	// create the credential file, or truncate (clear) it if it exists
	f, err := os.Create(s.credentialPath)
	if err != nil {
		return nil, authErr("failed to create credential file", err)
	}
	return f, nil
}

func (s *credStore) loadDockerCredentials() (*dockerCredentials, error) {
	path := s.credentialPath
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var creds dockerCredentials
	if err := json.NewDecoder(f).Decode(&creds); err != nil {
		return nil, authErr("failed to decode credentials from "+path, err)
	}

	return &creds, nil
}

func (s *credStore) setDockerCredentials(creds *dockerCredentials) error {
	f, err := s.createCredentialFile()
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewEncoder(f).Encode(creds)
}

// dockerCredentialPath returns the full path of our Docker credential store.
func dockerCredentialPath() (string, error) {
	if path := os.Getenv(credentialStoreEnvVar); strings.TrimSpace(path) != "" {
		return path, nil
	}

	configPath, err := util.SdkConfigPath()
	if err != nil {
		return "", authErr("couldn't construct config path", err)
	}
	return filepath.Join(configPath, credentialStoreFilename), nil
}

func authErr(message string, err error) error {
	if err == nil {
		return fmt.Errorf("docker-credential-gcr/store: %s", message)
	}
	return fmt.Errorf("docker-credential-gcr/store: %s: %v", message, err)
}
