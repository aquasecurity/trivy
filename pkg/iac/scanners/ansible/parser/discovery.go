package parser

import (
	"fmt"
	"io/fs"
	"path"
	"slices"

	"github.com/bmatcuk/doublestar/v4"
)

// FindProjects locates Ansible project roots within fsys starting from root.
// A directory is recognized as a project root if it contains key files or directories
// like ansible.cfg, inventory, group_vars, host_vars, roles, playbooks, or YAML playbooks.
//
// Returns a slice of project root paths.
func FindProjects(fsys fs.FS, root string) ([]string, error) {
	var roots []string
	walkFn := func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {
			return nil
		}

		if isAnsibleProject(fsys, filePath) {
			roots = append(roots, filePath)
			return fs.SkipDir
		}

		return nil
	}

	if err := fs.WalkDir(fsys, root, walkFn); err != nil {
		return nil, fmt.Errorf("walk dir: %w", err)
	}

	return roots, nil
}

func isAnsibleProject(fsys fs.FS, dir string) bool {
	anchors := []string{
		"ansible.cfg",
		"inventory", "group_vars", "host_vars", "roles", "playbooks",
	}

	for _, name := range anchors {
		if pathExists(fsys, path.Join(dir, name)) {
			return true
		}
	}

	if entries, err := doublestar.Glob(fsys, dir+"/roles/**/{tasks,defaults,vars}"); err == nil && len(entries) > 0 {
		return true
	}

	if entries, err := doublestar.Glob(fsys, dir+"/*.{yml,yaml}"); err == nil && len(entries) > 0 {
		for _, entry := range entries {
			if isPlaybookFile(fsys, entry) {
				return true
			}
		}
	}

	return false
}

func isPlaybookFile(fsys fs.FS, filePath string) bool {
	data, err := fs.ReadFile(fsys, filePath)
	if err != nil {
		return false
	}

	var plays []*Play
	if err := decodeYAML(data, &plays); err != nil {
		return false
	}

	return slices.ContainsFunc(plays, func(play *Play) bool {
		return play.Hosts() != ""
	})
}

func pathExists(fsys fs.FS, filePath string) bool {
	_, err := fs.Stat(fsys, filePath)
	return err == nil
}
