package hook

import (
	"github.com/aquasecurity/fanal/types"
	"golang.org/x/xerrors"
)

var (
	registeredHooks = map[Type]hook{}
)

type hook interface {
	Type() Type
	Version() int
	Hook(*types.BlobInfo) error
}

// RegisterHook registers a mutating hook
func RegisterHook(h hook) {
	registeredHooks[h.Type()] = h
}

func DeregisterHook(t Type) {
	delete(registeredHooks, t)
}

type Manager struct {
	disabled []Type
}

func NewManager(disabled []Type) Manager {
	return Manager{
		disabled: disabled,
	}
}

func (m Manager) Versions() map[string]int {
	versions := map[string]int{}
	for _, h := range registeredHooks {
		if isDisabled(h, m.disabled) {
			versions[string(h.Type())] = 0
			continue
		}
		versions[string(h.Type())] = h.Version()
	}
	return versions
}

func (m Manager) CallHooks(blob *types.BlobInfo) error {
	for _, h := range registeredHooks {
		if isDisabled(h, m.disabled) {
			continue
		}

		if err := h.Hook(blob); err != nil {
			return xerrors.Errorf("hook error: %w", err)
		}
	}
	return nil
}

func isDisabled(h hook, disabled []Type) bool {
	for _, d := range disabled {
		if h.Type() == d {
			return true
		}
	}
	return false
}
