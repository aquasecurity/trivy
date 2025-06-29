package extension

import (
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/flag"
)

var flagExtensions = make(map[string]FlagExtension)

func RegisterFlagExtension(extension FlagExtension) {
	flagExtensions[extension.Name()] = extension
}

func DeregisterFlagExtension(name string) {
	delete(flagExtensions, name)
}

// FlagExtension is an extension that allows adding custom CLI flags.
type FlagExtension interface {
	Name() string

	// CustomFlagGroup returns custom flag group to be added to Trivy CLI.
	// The command parameter specifies which command the flags are for.
	// If the command is empty, the flags will be applied to all commands.
	CustomFlagGroup(command string) flag.FlagGroup
}

// CustomFlagGroups collects all flag groups from registered extensions for a specific command.
func CustomFlagGroups(command string) []flag.FlagGroup {
	var flagGroups []flag.FlagGroup
	for _, e := range flagExtensions {
		group := e.CustomFlagGroup(command)
		if lo.IsNil(group) {
			continue
		}
		flagGroups = append(flagGroups, group)
	}
	return flagGroups
}
