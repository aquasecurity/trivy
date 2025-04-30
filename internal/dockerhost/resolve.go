// SPDX-License-Identifier: Apache-2.0
package dockerhost

import (
    "encoding/json"
    "io/fs"
    "os"
    "path/filepath"
    "strings"
)

const defaultSocket = "unix:///var/run/docker.sock"

type metaFile struct {
    Name      string `json:"Name"`
    Endpoints map[string]struct {
        Host string `json:"Host"`
    } `json:"Endpoints"`
}

// Resolve decides which Docker daemon Trivy should talk to.
func Resolve(flagHost string) string {
    // 1 --docker-host flag
    if flagHost != "" {
        return flagHost
    }
    // 2 DOCKER_HOST env
    if h := os.Getenv("DOCKER_HOST"); h != "" {
        return h
    }

    // 3 which context name?
    ctxName := os.Getenv("DOCKER_CONTEXT")
    if ctxName == "" {
        if home, err := os.UserHomeDir(); err == nil {
            raw, _ := os.ReadFile(filepath.Join(home, ".docker", "config.json"))
            var cfg struct{ CurrentContext string `json:"currentContext"` }
            _ = json.Unmarshal(raw, &cfg)
            ctxName = cfg.CurrentContext
        }
    }
    if ctxName == "" || ctxName == "default" {
        return defaultSocket
    }

    // 4 look for ~/.docker/contexts/meta/**/meta.json with matching Name
    home, err := os.UserHomeDir()
    if err != nil {
        return defaultSocket
    }
    base := filepath.Join(home, ".docker", "contexts", "meta")

    var host string
    filepath.WalkDir(base, func(path string, d fs.DirEntry, _ error) error {
        if d == nil || d.IsDir() || !strings.EqualFold(d.Name(), "meta.json") {
            return nil
        }
        raw, err := os.ReadFile(path)
        if err != nil {
            return nil
        }
        var mf metaFile
        if json.Unmarshal(raw, &mf) != nil || mf.Name != ctxName {
            return nil
        }
        if ep, ok := mf.Endpoints["docker"]; ok && ep.Host != "" {
            host = ep.Host
            return fs.SkipAll // found it → stop walking
        }
        return nil
    })

    if host != "" {
        return host
    }
    return defaultSocket
}
