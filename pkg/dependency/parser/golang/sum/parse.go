package sum

import (
	"bufio"
	"io"
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/xerrors"
)

// Entry holds the go.sum lines of one module version.
type Entry struct {
	Module module.Version
	// ModuleSum is the checksum of the whole module, e.g. "h1:...". It is empty
	// if go.sum has only the checksum of the module's go.mod file.
	ModuleSum string
}

// Parse returns the entries of a go.sum file, one per module version, in the order
// of their first line.
func Parse(r io.Reader) ([]Entry, error) {
	var entries []Entry
	index := make(map[module.Version]int)

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		s := strings.Fields(scanner.Text())
		if len(s) < 2 {
			continue
		}

		ver, goMod := strings.CutSuffix(s[1], "/go.mod")
		mod := module.Version{Path: s[0], Version: ver}
		i, ok := index[mod]
		if !ok {
			i = len(entries)
			index[mod] = i
			entries = append(entries, Entry{Module: mod})
		}

		if !goMod && len(s) >= 3 {
			entries[i].ModuleSum = s[2]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, xerrors.Errorf("scan error: %w", err)
	}

	return entries, nil
}
