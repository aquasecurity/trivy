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

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/GoogleCloudPlatform/docker-credential-gcr/util"
)

const (
	configFileEnvVariable = "DOCKER_CREDENTIAL_GCR_CONFIG"
	configFileName        = "docker_credential_gcr_config.json"
)

// DefaultTokenSources designates which default source(s) should be used to
// fetch a GCR access_token, and in which order.
var DefaultTokenSources = [...]string{"store", "gcloud", "env"}

// UserConfig describes
type UserConfig interface {
	TokenSources() []string
	SetTokenSources([]string) error
	DefaultToGCRAccessToken() bool
	SetDefaultToGCRAccessToken(bool) error
	ResetAll() error
}

// configFile describes the structure of the persistent config store.
type configFile struct {
	TokenSrcs         []string `json:"TokenSources,omitempty"`
	DefaultToGCRToken bool     `json:"DefaultToGCRToken,omitempty"`

	// package private helper, made a member variable and exposed for testing
	persist func(*configFile) error
}

// LoadUserConfig returns the UserConfig which provides user-configurable
// application settings, or a new on if it doesn't exist.
func LoadUserConfig() (UserConfig, error) {
	config, err := load()
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		config = &configFile{}
	}
	config.persist = persist
	return config, nil
}

func load() (*configFile, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var config configFile
	if err := json.NewDecoder(f).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to load config from %s: %v", path, err)
	}

	return &config, nil
}

// TokenSources returns the configured token sources, or the DefaultTokenSources
// if none are set.
func (c *configFile) TokenSources() []string {
	if len(c.TokenSrcs) == 0 { // if nil or empty
		return DefaultTokenSources[:]
	}
	ret := make([]string, len(c.TokenSrcs))
	copy(ret, c.TokenSrcs)
	return ret
}

// SetTokenSources sets (and persists) the token sources. Valid token sources
// are defined by config.SupportedGCRTokenSources.
func (c *configFile) SetTokenSources(newSources []string) error {
	if len(newSources) == 0 {
		newSources = nil
	}
	// Don't touch the file unless we need to.
	if equal(newSources, c.TokenSrcs) {
		return nil
	}

	for _, source := range newSources {
		if _, supported := SupportedGCRTokenSources[source]; !supported {
			return fmt.Errorf("Unsupported token source: %s", source)
		}
	}

	c.TokenSrcs = newSources

	return c.persist(c)
}

func (c *configFile) DefaultToGCRAccessToken() bool {
	return c.DefaultToGCRToken
}

func (c *configFile) SetDefaultToGCRAccessToken(defaultToGCR bool) error {
	c.DefaultToGCRToken = defaultToGCR
	return c.persist(c)
}

func persist(c *configFile) error {
	f, err := createConfigFile()
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewEncoder(f).Encode(c)
}

func equal(a, b []string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ResetAll clears all user configuration.
func (c *configFile) ResetAll() error {
	err := deleteConfigFile()
	if err != nil {
		return err
	}
	c.TokenSrcs = nil
	c.DefaultToGCRToken = false
	return nil
}

func deleteConfigFile() error {
	path, err := configPath()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Remove(path)
}

// createConfigFile creates (or truncates) and returns an os.File for the
// user config.
func createConfigFile() (*os.File, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	// create the gcloud config dir, if it doesnt exist
	if err = os.MkdirAll(filepath.Dir(path), 0777); err != nil {
		return nil, err
	}

	// create or truncate the config file and return it
	return os.Create(path)
}

// configPath returns the full path of our user config file.
func configPath() (string, error) {
	if path := os.Getenv(configFileEnvVariable); strings.TrimSpace(path) != "" {
		return path, nil
	}

	sdkConfigPath, err := util.SdkConfigPath()
	if err != nil {
		return "", fmt.Errorf("couldn't construct config path: %v", err)
	}
	return filepath.Join(sdkConfigPath, configFileName), nil
}
