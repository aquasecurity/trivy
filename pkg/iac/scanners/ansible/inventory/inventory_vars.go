package inventory

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"maps"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/fsutils"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
)

type VarScope int

const (
	ScopeGroupAll VarScope = iota
	ScopeGroupSpecific
	ScopeHost
)

func (s VarScope) String() string {
	switch s {
	case ScopeGroupAll:
		return "group_vars/all (external)"
	case ScopeGroupSpecific:
		return "group_vars/* (external)"
	case ScopeHost:
		return "host_vars (external)"
	default:
		return ""
	}
}

func fileBaseName(p string) string {
	return strings.TrimSuffix(filepath.Base(p), filepath.Ext(p))
}

func isAllGroup(path string) bool {
	return fileBaseName(path) == "all"
}

func notAllGroup(path string) bool {
	return !isAllGroup(path)
}

func InventoryVarsSources(fileSrc fsutils.FileSource) []VarsSource {
	return []VarsSource{
		{
			FileSrc:  fileSrc.Join("group_vars"),
			Scope:    ScopeGroupAll,
			Priority: vars.InvExtAllGroupPriority,
			Match:    isAllGroup,
		},
		{
			FileSrc:  fileSrc.Join("group_vars"),
			Scope:    ScopeGroupSpecific,
			Priority: vars.InvExtGroupPriority,
			Match:    notAllGroup,
		},
		{
			FileSrc:  fileSrc.Join("host_vars"),
			Scope:    ScopeHost,
			Priority: vars.InvExtHostPriority,
		},
	}
}

func PlaybookVarsSources(fileSrc fsutils.FileSource) []VarsSource {
	return []VarsSource{
		{
			FileSrc:  fileSrc.Join("group_vars"),
			Scope:    ScopeGroupAll,
			Priority: vars.PbExtAllGroupPriority,
			Match:    isAllGroup,
		},
		{
			FileSrc:  fileSrc.Join("group_vars"),
			Scope:    ScopeGroupSpecific,
			Priority: vars.PbExtGroupPriority,
			Match:    notAllGroup,
		},
		{
			FileSrc:  fileSrc.Join("host_vars"),
			Scope:    ScopeHost,
			Priority: vars.PbExtHostPriority,
		},
	}
}

type VarsSource struct {
	FileSrc  fsutils.FileSource
	Scope    VarScope // variables scope
	Priority vars.VarPriority
	Match    func(path string) bool
}

// LoadedVars stores all loaded variables organized by scope and key (host or group).
// The first map is by VarScope, the second by host/group name, each holding Vars.
type LoadedVars map[VarScope]map[string]vars.Vars

func (v *LoadedVars) Merge(other LoadedVars) {
	if *v == nil {
		*v = make(LoadedVars)
	}
	for scope, objs := range other {
		if (*v)[scope] == nil {
			(*v)[scope] = make(map[string]vars.Vars)
		}
		for name, targetVars := range objs {
			existing, ok := (*v)[scope][name]
			if !ok {
				(*v)[scope][name] = targetVars
				continue
			}
			merged := make(vars.Vars)
			maps.Copy(merged, existing)
			maps.Copy(merged, targetVars)
			(*v)[scope][name] = merged
		}
	}
}

func LoadVars(sources []VarsSource) LoadedVars {
	logger := log.WithPrefix("ansible")
	allVars := make(LoadedVars)

	for _, src := range sources {
		srcVars, err := LoadSourceVars(src)
		if err != nil {
			continue
		}

		if allVars[src.Scope] == nil {
			allVars[src.Scope] = make(map[string]vars.Vars)
		}

		for key, v := range srcVars {
			allVars[src.Scope][key] = vars.MergeVars(allVars[src.Scope][key], v)

			logger.Debug("Loaded vars from directory",
				log.String("scope", src.Scope.String()), log.String("target", key))
		}
	}

	return allVars
}

func LoadSourceVars(src VarsSource) (map[string]vars.Vars, error) {
	info, err := src.FileSrc.Stat()
	if err != nil {
		return nil, err
	}

	result := make(map[string]vars.Vars)

	if info.IsDir() {
		entries, err := listEntries(src.FileSrc)
		if err != nil {
			return nil, err
		}

		fsutils.SortDirsFirstAlpha(entries)

		for _, e := range entries {
			name := e.Name()
			entrySrc := src.FileSrc.Join(name)
			target := strings.TrimSuffix(name, path.Ext(name))

			if src.Match != nil && !src.Match(entrySrc.Path) {
				continue
			}

			if e.IsDir() {
				walkFn := func(fileSrc fsutils.FileSource, d fs.DirEntry) error {
					if !d.IsDir() {
						plain := processFile(fileSrc)
						v := vars.NewVars(plain, src.Priority)
						result[target] = vars.MergeVars(result[target], v)
					}
					return nil
				}
				if err := fsutils.WalkDirsFirstAlpha(entrySrc, walkFn); err != nil {
					log.WithPrefix("ansible").Debug("Walk error", log.FilePath(entrySrc.Path))
					continue
				}
			} else {
				plain := processFile(entrySrc)
				v := vars.NewVars(plain, src.Priority)
				result[target] = vars.MergeVars(result[target], v)
			}

		}
	}

	return result, nil
}

func processFile(fileSrc fsutils.FileSource) vars.PlainVars {
	if shouldSkipFile(fileSrc.Path) {
		return nil
	}

	v, err := readVars(fileSrc)
	if err != nil {
		log.WithPrefix("ansible").Debug("Failed to read vars",
			log.FilePath(fileSrc.Path), log.Err(err))
		return nil
	}

	return v
}

// listEntries returns directory entries sorted alphabetically,
// with directories listed before files.
//
// At the top level, if a directory and a file share the same
// base name, the directory takes precedence and the file is ignored.
//
// For example, if "host_vars/group_vars" contains both "all/"
// and "all.yaml", "all.yaml" will be skipped in favor of the directory.
func listEntries(root fsutils.FileSource) ([]fs.DirEntry, error) {
	entries, err := root.ReadDir()
	if err != nil {
		return nil, err
	}

	dirs := set.New[string]()
	for _, e := range entries {
		if e.IsDir() {
			dirs.Append(e.Name())
		}
	}

	filtered := make([]fs.DirEntry, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			name := strings.TrimSuffix(e.Name(), path.Ext(e.Name()))
			if dirs.Contains(name) {
				continue
			}
		}
		filtered = append(filtered, e)
	}
	return filtered, nil
}

func shouldSkipFile(filePath string) bool {
	base := path.Base(filePath)
	if strings.HasPrefix(base, ".") || strings.HasSuffix(base, "~") {
		return true
	}
	if !slices.Contains(vars.VarFilesExtensions, filepath.Ext(base)) {
		return true
	}
	return false
}

func readVars(fileSrc fsutils.FileSource) (map[string]any, error) {
	data, err := fileSrc.ReadFile()
	if err != nil {
		return nil, err
	}

	var vars map[string]any
	dataTrim := bytes.TrimSpace(data)
	if len(dataTrim) > 0 && dataTrim[0] == '{' {
		err = json.Unmarshal(dataTrim, &vars)
	} else {
		err = yaml.Unmarshal(dataTrim, &vars)
	}
	if err != nil {
		return nil, err
	}

	return vars, nil
}
