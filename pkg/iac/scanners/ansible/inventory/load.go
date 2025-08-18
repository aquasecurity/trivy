package inventory

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

const defaultHostsFile = "/etc/ansible/hosts"

// InventorySource defines a source from which inventory data can be loaded.
//
// It may point to filesystem directories containing hosts files and
// variables, or directly provide an inline list of hosts.
//
// The source can contain either InlineHosts or a combination of HostsDirs and VarsDir.
// HostsDirs may be empty.
type InventorySource struct {
	// HostsDirs is a list of paths to directories containing hosts files.
	HostsDirs []string

	// VarsDir is the path to the directory containing host_vars and group_vars.
	VarsDir string

	// InlineHosts is a list of hosts provided directly in-memory instead of
	// loading them from files.
	InlineHosts []string
}

type LoadOptions struct {
	// InventoryPath is the path from the "inventory" config
	// in ansible.cfg.
	InventoryPath string

	// Sources are explicit inventory sources (CLI args, env vars, etc.).
	Sources []string
}

// LoadAuto resolves inventory sources from configuration, environment variables,
// and command-line flags, then loads the resulting inventory.
func LoadAuto(fsys fs.FS, opts LoadOptions) (*Inventory, error) {
	sources, err := ResolveSources(fsys, opts)
	if err != nil {
		return nil, xerrors.Errorf("resolve inventory sources: %w", err)
	}

	inv, err := LoadFromSources(fsys, sources)
	if err != nil {
		return nil, xerrors.Errorf("load from sources: %w", err)
	}

	return inv, nil
}

// ResolveSources resolves one or more Ansible inventory sources into a list of InventorySource.
//
// If `sources` is empty, the function falls back to defaults:
//   - cfg.Inventory directory, if configured
//   - "/etc/ansible/hosts" file, if no config is provided
//
// Inline host lists are detected by the presence of commas (e.g., "host1,host2").
//
// The returned slice of InventorySource can be used to load hosts, group_vars, and host_vars
// for each inventory source.
func ResolveSources(fsys fs.FS, opts LoadOptions) ([]InventorySource, error) {
	if len(opts.Sources) == 0 {
		if opts.InventoryPath != "" {
			src, err := resolveSource(fsys, opts.InventoryPath, set.New[string]())
			if err != nil {
				return nil, xerrors.Errorf("resolve source from config: %w", err)
			}
			return []InventorySource{src}, nil
		}
		return defaultInventorySources()
	}

	var result []InventorySource

	seen := set.New[string]()

	for _, s := range opts.Sources {
		src, err := resolveSource(fsys, s, seen)
		if err != nil {
			return nil, err
		}
		result = append(result, src)
	}

	return result, nil
}

func makeFileSource(file string) InventorySource {
	return InventorySource{
		HostsDirs: []string{file},
		VarsDir:   filepath.Dir(file),
	}
}

// defaultInventorySources returns sources from cfg or system defaults.
func defaultInventorySources() ([]InventorySource, error) {
	// TODO: use ANSIBLE_INVENTORY env
	if fsutils.FileExists(defaultHostsFile) {
		return []InventorySource{makeFileSource(defaultHostsFile)}, nil
	}
	return nil, nil
}

// resolveSource resolves a single source path: file, dir, or dir tree.
func resolveSource(fsys fs.FS, path string, seen set.Set[string]) (InventorySource, error) {
	// TODO: handle inline host list, e.g. "host1,host2"
	if looksLikeInlineHosts(path) {
		return resolveInlineHosts(path)
	}

	info, err := fs.Stat(fsys, path)
	if err != nil {
		return InventorySource{}, err
	}

	if !info.IsDir() {
		return makeFileSource(path), nil
	}

	return walkInventoryDir(fsys, path, seen)
}

// Stub: determine if path looks like inline host list
func looksLikeInlineHosts(path string) bool {
	// simple heuristic: contains comma but no wildcard
	return strings.Contains(path, ",")
}

// Stub: resolve inline hosts
func resolveInlineHosts(path string) (InventorySource, error) {
	hosts := strings.Split(path, ",")
	if len(hosts) > 0 {
		return InventorySource{
			InlineHosts: hosts,
		}, nil
	}
	return InventorySource{}, nil
}

// walkInventoryDir recursively walks a directory and returns all inventory dirs containing files.
func walkInventoryDir(fsys fs.FS, root string, seen set.Set[string]) (InventorySource, error) {
	result := InventorySource{
		VarsDir: root,
	}

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
			if !seen.Contains(cleanPath) {
				seen.Append(cleanPath)
				result.HostsDirs = append(result.HostsDirs, cleanPath)
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

// LoadFromSources loads inventory files or directories from
// the given sources and merges them into a single Inventory.
func LoadFromSources(fsys fs.FS, sources []InventorySource) (*Inventory, error) {
	res := newInlineInventory(nil)

	externalVars := make(vars.LoadedVars)

	for _, src := range sources {

		if len(src.InlineHosts) > 0 {
			inv := newInlineInventory(src.InlineHosts)
			res.Merge(inv)
			continue
		}

		for _, hostsDir := range src.HostsDirs {
			entries, err := fs.ReadDir(fsys, hostsDir)
			if err != nil {
				log.Debug("Failed to read dir with hosts files", log.FilePath(hostsDir), log.Err(err))
				continue
			}

			for _, entry := range entries {
				filePath := path.Join(hostsDir, entry.Name())
				b, err := fs.ReadFile(fsys, filePath)
				if err != nil {
					log.Debug("Failed to read hosts file", log.FilePath(filePath), log.Err(err))
					continue
				}

				inv, err := ParseYAML(b)
				if err != nil {
					log.Debug("Failed to parse hosts file", log.FilePath(filePath), log.Err(err))
					continue
				}

				res.Merge(inv)
			}
		}

		vars := vars.LoadVars(vars.InventoryVarsSources(fsys, src.VarsDir))
		externalVars.Merge(vars)
	}

	res.ApplyVars(externalVars)
	return res, nil
}

func newInlineInventory(hosts []string) *Inventory {
	return &Inventory{
		groups: map[string]*Group{
			"all": {},
			"ungrouped": {
				Parents: []string{"all"},
			},
		},
		hosts: lo.SliceToMap(hosts, func(h string) (string, *Host) {
			return h, &Host{}
		}),
		hostGroups: lo.SliceToMap(hosts, func(h string) (string, []string) {
			return h, []string{"all", "ungrouped"}
		}),
	}
}
