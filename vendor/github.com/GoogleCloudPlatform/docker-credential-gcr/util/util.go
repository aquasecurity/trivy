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
Package util contains utilities which are shared between packages.
*/
package util

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
)

// SdkConfigPath tries to return the directory where the gcloud config is
// located.
func SdkConfigPath() (string, error) {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("APPDATA"), "gcloud"), nil
	}
	homeDir := unixHomeDir()
	if homeDir == "" {
		return "", errors.New("unable to get current user home directory: os/user lookup failed; $HOME is empty")
	}
	return filepath.Join(homeDir, ".config", "gcloud"), nil
}

// unixHomeDir returns the user's home directory.  Note that $HOME has
// precedence over records in the password database since the credential helper
// may be running under a different UID in a user namespace.
func unixHomeDir() string {
	homeDir := os.Getenv("HOME")
	if homeDir != "" {
		return homeDir
	}
	if usr, err := user.Current(); err == nil {
		return usr.HomeDir
	}
	return ""
}
