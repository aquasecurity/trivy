package inventory

import (
	"io/fs"
	"os"
	"path"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/fsutils"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
)

const defaultHostsFile = "/etc/ansible/hosts"

// InventorySource represents a source from which inventory data can be loaded.
type InventorySource interface {
	isInventorySource()
}

type InlineHostsSource struct {
	// Hosts is a list of hosts provided directly in-memory instead of
	// loading them from files.
	Hosts []string
}

func (InlineHostsSource) isInventorySource() {}

type HostsDirsSource struct {
	// Dirs is a list of paths to directories containing hosts files.
	Dirs []fsutils.FileSource
	// VarsDir is the path to the directory containing host_vars and group_vars.
	VarsDir fsutils.FileSource
}

func (HostsDirsSource) isInventorySource() {}

type HostFileSource struct {
	// File is a path to hosts file.
	File fsutils.FileSource
	// VarsDir is the path to the directory containing host_vars and group_vars.
	VarsDir fsutils.FileSource
}

func (HostFileSource) isInventorySource() {}

type LoadOptions struct {
	// InventoryPath is the path from the "inventory" config
	// in ansible.cfg.
	InventoryPath string

	// Sources are explicit inventory sources (CLI args, env vars, etc.).
	Sources []string
}

// LoadAuto resolves inventory sources from configuration, environment variables,
// and command-line flags, then loads the resulting inventory.
func LoadAuto(fsys fs.FS, opts LoadOptions) *Inventory {
	sources, err := ResolveSources(fsys, opts)
	if err != nil {
		log.WithPrefix("ansible").Debug("Failed to resolve inventory sources", log.Err(err))
	}

	if len(sources) == 0 {
		log.WithPrefix("ansible").Debug(
			"No inventory sources provided, falling back to implicit host 'localhost'")
		// https://docs.ansible.com/ansible/latest/inventory/implicit_localhost.html#implicit-localhost
		return newInlineInventory([]string{"localhost"})
	}

	return LoadFromSources(sources)
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
	logger := log.WithPrefix("ansible")
	if len(opts.Sources) == 0 {
		if opts.InventoryPath != "" {
			// TODO: This is comma-separated list of Ansible inventory sources
			logger.Debug("Resolve inventory source from config", log.FilePath(opts.InventoryPath))
			fileSrc := fsutils.NewFileSource(fsys, opts.InventoryPath)
			src, err := resolveSource(fileSrc, set.New[string]())
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
		logger.Debug("Resolve inventory source", log.String("source", s))
		fileSrc := fsutils.NewFileSource(fsys, s)
		src, err := resolveSource(fileSrc, seen)
		if err != nil {
			return nil, err
		}
		result = append(result, src)
	}

	return result, nil
}

func makeHostFileSource(fileSrc fsutils.FileSource) InventorySource {
	return HostFileSource{
		File:    fileSrc,
		VarsDir: fileSrc.Dir(),
	}
}

// defaultInventorySources returns sources from cfg or system defaults.
func defaultInventorySources() ([]InventorySource, error) {
	// TODO: use ANSIBLE_INVENTORY env
	if _, err := os.Stat(defaultHostsFile); err == nil {
		log.WithPrefix("ansible").Debug("Use default hosts file", log.FilePath(defaultHostsFile))
		fileSrc := fsutils.NewFileSource(nil, defaultHostsFile)
		return []InventorySource{makeHostFileSource(fileSrc)}, nil
	}
	return nil, nil
}

// resolveSource resolves a single source path: file, dir, or dir tree.
func resolveSource(fileSrc fsutils.FileSource, seen set.Set[string]) (InventorySource, error) {
	// TODO: handle inline host list, e.g. "host1,host2"
	if looksLikeInlineHosts(fileSrc.Path) {
		return resolveInlineHosts(fileSrc.Path)
	}

	info, err := fileSrc.Stat()
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return makeHostFileSource(fileSrc), nil
	}

	return walkInventoryDir(fileSrc, seen)
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
		return InlineHostsSource{
			Hosts: hosts,
		}, nil
	}
	return nil, nil
}

// walkInventoryDir recursively walks a directory and returns all inventory dirs containing files.
func walkInventoryDir(fileSrc fsutils.FileSource, seen set.Set[string]) (InventorySource, error) {
	result := HostsDirsSource{
		VarsDir: fileSrc,
	}

	if err := fileSrc.WalkDirFS(func(fileSrc fsutils.FileSource, de fs.DirEntry) error {
		if !de.IsDir() {
			return nil
		}

		// TODO: allow files with no extension or with the extensions .json, .yml, or .yaml
		base := path.Base(fileSrc.Path)
		if base == "group_vars" || base == "host_vars" {
			// TODO: use fs.SkipDir?
			return nil // skip vars directories
		}

		hasFiles, err := dirHasFiles(fileSrc)
		if err != nil {
			log.WithPrefix("ansible").Debug("Failed to read directory",
				log.FilePath(fileSrc.Path), log.Err(err))
			return nil
		}

		if !hasFiles {
			return nil
		}

		cleanPath := path.Clean(fileSrc.Path)
		if !seen.Contains(cleanPath) {
			seen.Append(cleanPath)
			result.Dirs = append(result.Dirs, fileSrc)
		}

		return nil
	}); err != nil {
		return nil, xerrors.Errorf("walk dir: %w", err)
	}

	return result, nil
}

// dirHasFiles returns true if the directory contains at least one non-directory entry.
func dirHasFiles(fileSrc fsutils.FileSource) (bool, error) {
	ents, err := fileSrc.ReadDir()
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
//
// When multiple inventory sources are provided, Ansible merges
// variables in the order the sources are specified.
// See https://docs.ansible.com/ansible/latest/inventory_guide/intro_inventory.html#managing-inventory-variable-load-order
func LoadFromSources(sources []InventorySource) *Inventory {
	logger := log.WithPrefix("ansible")

	res := newInventory()
	externalVars := make(LoadedVars)

	for _, source := range sources {

		// Ansible loads host and group variable files by searching paths
		// relative to the inventory source.
		// See https://docs.ansible.com/ansible/latest/inventory_guide/intro_inventory.html#organizing-host-and-group-variables
		switch src := source.(type) {
		case InlineHostsSource:
			logger.Debug("Processing inline hosts source", log.Any("hosts", src.Hosts))
			inv := newInlineInventory(src.Hosts)
			res.Merge(inv)
		case HostFileSource:
			inv, err := readAndParseHosts(src.File)
			if err != nil {
				logger.Debug("Failed to parse hosts file",
					log.FilePath(src.File.Path), log.Err(err))
				continue
			}
			res.Merge(inv)
			logger.Debug("Loaded hosts file", log.FilePath(src.File.Path))

			vars := LoadVars(InventoryVarsSources(src.VarsDir))
			externalVars.Merge(vars)
		case HostsDirsSource:
			for _, hostsDirSrc := range src.Dirs {
				entries, err := hostsDirSrc.ReadDir()
				if err != nil {
					logger.Debug("Failed to read dir with hosts files",
						log.FilePath(hostsDirSrc.Path), log.Err(err))
					continue
				}

				for _, entry := range entries {
					hostFileSrc := hostsDirSrc.Join(entry.Name())
					inv, err := readAndParseHosts(hostFileSrc)
					if err != nil {
						logger.Debug("Failed to parse hosts file",
							log.FilePath(hostFileSrc.Path), log.Err(err))
						continue
					}
					res.Merge(inv)
					logger.Debug("Loaded hosts file", log.FilePath(hostFileSrc.Path))
				}
			}
			vars := LoadVars(InventoryVarsSources(src.VarsDir))
			externalVars.Merge(vars)
		}
	}

	res.applyVars(externalVars)
	return res
}

func readAndParseHosts(fileSrc fsutils.FileSource) (*Inventory, error) {
	b, err := fileSrc.ReadFile()
	if err != nil {
		return nil, err
	}

	if inv, err := ParseYAML(b); err == nil {
		return inv, nil
	}

	return ParseINI(b)
}
