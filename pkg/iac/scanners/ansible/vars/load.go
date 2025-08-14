package vars

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

type VarScope int

const (
	ScopeGroupAll VarScope = iota
	ScopeGroupSpecific
	ScopeHost
)

func fileBaseName(p string) string {
	return strings.TrimSuffix(filepath.Base(p), filepath.Ext(p))
}

func isAllGroup(path string) bool {
	return fileBaseName(path) == "all"
}

func notAllGroup(path string) bool {
	return !isAllGroup(path)
}

func InventoryVarsSources(fsys fs.FS, dir string) []VarsSource {
	return []VarsSource{
		{FS: fsys, Path: path.Join(dir, "group_vars"), Scope: ScopeGroupAll, Match: isAllGroup},
		{FS: fsys, Path: path.Join(dir, "group_vars"), Scope: ScopeGroupSpecific, Match: notAllGroup},
		{FS: fsys, Path: path.Join(dir, "host_vars"), Scope: ScopeHost},
	}
}

func PlaybookVarsSources(fsys fs.FS, dir string) []VarsSource {
	return []VarsSource{
		{FS: fsys, Path: path.Join(dir, "group_vars"), Scope: ScopeGroupAll, Match: isAllGroup},
		{FS: fsys, Path: path.Join(dir, "group_vars"), Scope: ScopeGroupSpecific, Match: notAllGroup},
		{FS: fsys, Path: path.Join(dir, "host_vars"), Scope: ScopeHost},
	}
}

type VarsSource struct {
	FS    fs.FS
	Path  string
	Scope VarScope // variables scope
	Match func(path string) bool
}

// Result of the loaded variable file
type LoadedVars struct {
	// File's full name
	File string
	// The name of the directory. This can be used as a host or group name.
	Target string
	// TODO: do not use enumeration, as variables can be loaded for the role.
	// The scope of variables, such as the host or group
	Scope VarScope

	Vars Vars
}

type VarsLoader struct{}

func (l VarsLoader) Load(sources []VarsSource) []LoadedVars {
	var allVars []LoadedVars

	for _, src := range sources {
		srcVars, err := loadSourceVars(src)
		if err != nil {
			continue
		}
		allVars = append(allVars, srcVars...)
	}

	return allVars
}

var allowedVarsExt = []string{"", ".yml", ".yaml", ".json"}

func loadSourceVars(src VarsSource) ([]LoadedVars, error) {
	info, err := fs.Stat(src.FS, src.Path)
	if err != nil {
		return nil, err
	}

	var result []LoadedVars

	if info.IsDir() {
		entries, _ := fs.ReadDir(src.FS, src.Path)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}

			if strings.HasPrefix(e.Name(), ".") || strings.HasSuffix(e.Name(), "~") {
				continue
			}

			if !slices.Contains(allowedVarsExt, filepath.Ext(e.Name())) {
				continue
			}

			filePath := filepath.Join(src.Path, e.Name())
			if src.Match != nil && !src.Match(filePath) {
				continue
			}
			vars, err := readVars(src.FS, filePath)
			if err != nil {
				continue
			}
			result = append(result, LoadedVars{
				File:  filePath,
				Vars:  vars,
				Scope: src.Scope,
			})
		}
	} else if src.Match == nil || src.Match(src.Path) {
		// TODO: load only from a directory
		vars, err := readVars(src.FS, src.Path)
		if err != nil {
			return nil, err
		}
		result = append(result, LoadedVars{
			File:  src.Path,
			Vars:  vars,
			Scope: src.Scope,
		})
	}

	return result, nil
}

func readVars(fsys fs.FS, filePath string) (map[string]any, error) {
	data, err := fs.ReadFile(fsys, filePath)
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
