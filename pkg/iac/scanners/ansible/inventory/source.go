package inventory

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const defaultHostsFile = "/etc/ansible/hosts"

type InventorySource struct {
	HostsFile    string   // path to inventory file
	InventoryDir string   // root inventory directory (for hosts files and group_vars/host_vars)
	InlineHosts  []string // if source is an inline host list
}

// ResolveSources resolves one or more Ansible inventory sources into a list of InventorySource.
//
// An inventory source can be:
//  1. A directory containing inventory files (HostsFile empty, InventoryDir set)
//  2. A specific inventory file (HostsFile set, InventoryDir = directory of the file)
//  3. An inline host list (InlineHosts set, HostsFile and InventoryDir empty)
//
// If `sources` is empty, the function falls back to defaults:
//   - cfg.Inventory directory, if configured
//   - "/etc/ansible/hosts" file, if no config is provided
//
// Inline host lists are detected by the presence of commas (e.g., "host1,host2").
// Glob patterns (e.g., "inventory/*") are currently stubbed and will be supported later.
//
// The returned slice of InventorySource can be used to load hosts, group_vars, and host_vars
// for each inventory source.
func ResolveSources(fsys fs.FS, opts LoadOptions) ([]InventorySource, error) {
	if len(opts.Sources) == 0 {
		if opts.InventoryPath != "" {
			return resolveSource(fsys, opts.InventoryPath, make(map[string]struct{}))
		}
		return defaultInventorySources()
	}

	var result []InventorySource

	// TODO: use pkg/set
	seen := make(map[string]struct{})

	for _, s := range opts.Sources {
		srcs, err := resolveSource(fsys, s, seen)
		if err != nil {
			return nil, err
		}
		result = append(result, srcs...)
	}

	return result, nil
}

func makeDirSource(dir string) InventorySource {
	return InventorySource{
		InventoryDir: dir,
	}
}

func makeFileSource(file string) InventorySource {
	return InventorySource{
		HostsFile:    file,
		InventoryDir: filepath.Dir(file),
	}
}

// defaultInventorySources returns sources from cfg or system defaults.
func defaultInventorySources() ([]InventorySource, error) {
	// TODO: use ANSIBLE_INVENTORY env
	return []InventorySource{makeFileSource(defaultHostsFile)}, nil
}

// resolveSource resolves a single source path: file, dir, or dir tree.
func resolveSource(fsys fs.FS, path string, seen map[string]struct{}) ([]InventorySource, error) {
	// TODO: handle inline host list, e.g. "host1,host2"
	if looksLikeInlineHosts(path) {
		return resolveInlineHosts(path)
	}

	// TODO: handle glob pattern, e.g. "inventory/*"
	if looksLikeGlob(path) {
		return resolveGlob(path)
	}

	info, err := fs.Stat(fsys, path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return []InventorySource{makeFileSource(path)}, nil
	}

	return walkInventoryDir(fsys, path, seen)
}

// Stub: determine if path looks like inline host list
func looksLikeInlineHosts(path string) bool {
	// simple heuristic: contains comma but no wildcard
	return strings.Contains(path, ",") && !looksLikeGlob(path)
}

// Stub: resolve inline hosts
func resolveInlineHosts(path string) ([]InventorySource, error) {
	hosts := strings.Split(path, ",")
	var result []InventorySource
	if len(hosts) > 0 {
		result = append(result, InventorySource{
			InlineHosts: hosts,
		})
	}
	return result, nil
}

// Stub: determine if path looks like glob pattern
func looksLikeGlob(path string) bool {
	return strings.ContainsAny(path, "*?[")
}

// Stub: resolve glob pattern
func resolveGlob(_ string) ([]InventorySource, error) {
	// placeholder, just return empty slice for now
	return nil, nil
}

// walkInventoryDir recursively walks a directory and returns all inventory dirs containing files.
func walkInventoryDir(fsys fs.FS, root string, seen map[string]struct{}) ([]InventorySource, error) {
	var result []InventorySource

	err := fs.WalkDir(fsys, root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {
			return nil
		}

		// TODO: allow files with no extension or with the extensions .json, .yml, or .yaml

		base := filepath.Base(path)
		if base == "group_vars" || base == "host_vars" {
			return nil // skip vars directories
		}

		hasFiles, _ := dirHasFiles(fsys, path)
		if hasFiles {
			cleanPath := filepath.Clean(path)
			if _, ok := seen[cleanPath]; !ok {
				seen[cleanPath] = struct{}{}
				result = append(result, makeDirSource(cleanPath))
			}
		}
		return nil
	})

	return result, err
}

// dirHasFiles returns true if the directory contains at least one non-directory entry.
func dirHasFiles(fsys fs.FS, dir string) (bool, error) {
	ents, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return false, err
	}
	for _, e := range ents {
		if !e.IsDir() {
			return true, nil
		}
	}
	return false, nil
}
