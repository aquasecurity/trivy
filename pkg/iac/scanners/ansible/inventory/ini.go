package inventory

import (
	"bufio"
	"bytes"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
	"github.com/aquasecurity/trivy/pkg/set"
)

const (
	sectionHosts = iota
	sectionVars
	sectionChildren
)

func ParseINI(data []byte) (*Inventory, error) {
	inv := newInventory()

	currentGroup := "ungrouped"
	sectionType := sectionHosts

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = removeComment(line)
		if line == "" {
			continue
		}

		// handle section
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {

			sectionName := line[1 : len(line)-1]
			parts := strings.SplitN(sectionName, ":", 2)
			currentGroup = parts[0]
			sectionType = sectionHosts

			// group related sections with :modifiers
			if len(parts) == 2 {
				switch parts[1] {
				case "vars":
					sectionType = sectionVars
				case "children":
					sectionType = sectionChildren
				}
			}
			continue
		}

		switch sectionType {
		case sectionHosts:
			fields := splitFields(line)
			if len(fields) == 0 {
				// skip empty line
				continue
			}

			hostName := fields[0]
			plainHostVars := make(vars.PlainVars)

			for _, f := range fields[1:] {
				kv := strings.SplitN(f, "=", 2)
				if len(kv) == 2 {
					plainHostVars[kv[0]] = kv[1]
				}
			}

			hostVars := vars.NewVars(plainHostVars, vars.InvFileHostPriority)
			inv.addHost(hostName, newHost(hostVars, set.New(currentGroup)))
		case sectionVars:
			kv := strings.SplitN(line, "=", 2)
			key := strings.TrimSpace(kv[0])
			var val string
			if len(kv) == 2 {
				val = strings.TrimSpace(kv[1])
			}
			plainGroupVars := vars.PlainVars{key: val}
			groupVars := vars.NewVars(plainGroupVars, vars.InvFileGroupPriority)
			inv.addGroup(currentGroup, newGroup(groupVars, set.New[string]()))
		case sectionChildren:
			inv.addGroup(line, newGroup(make(vars.Vars), set.New(currentGroup)))
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, xerrors.Errorf("file scan: %w", err)
	}

	inv.initDefaultGroups()
	return inv, nil
}

func removeComment(line string) string {
	var (
		inQuotes  bool
		quoteChar rune
	)

	for i, r := range line {
		switch r {
		case '"', '\'':
			if inQuotes {
				if r == quoteChar {
					inQuotes = false
				}
			} else {
				inQuotes = true
				quoteChar = r
			}
		case '#', ';':
			if !inQuotes {
				return strings.TrimSpace(line[:i])
			}
		}
	}
	return strings.TrimSpace(line)
}

func splitFields(input string) []string {
	var (
		inQuotes  bool
		quoteChar rune
		escape    bool
		field     strings.Builder
		fields    []string
	)

	flush := func() {
		if field.Len() > 0 {
			fields = append(fields, field.String())
			field.Reset()
		}
	}

	for _, r := range input {
		if escape {
			field.WriteRune(r)
			escape = false
			continue
		}

		switch r {
		case '\\':
			escape = true
		case '"', '\'':
			if !inQuotes {
				inQuotes = true
				quoteChar = r
				continue
			}

			if r == quoteChar {
				inQuotes = false
				continue
			}
			field.WriteRune(r)
		case ' ', '\t':
			if inQuotes {
				field.WriteRune(r)
			} else {
				flush()
			}
		default:
			field.WriteRune(r)
		}
	}
	flush()

	return fields
}
