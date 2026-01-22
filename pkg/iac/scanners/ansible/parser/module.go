package parser

// Module represents a logical module in a playbook or task.
// It wraps a Node and provides module-specific utility methods.
//
// All the data and metadata for the module is stored in the embedded Node.
type Module struct {
	*Node

	Name string
}

// IsFreeForm returns true if the module is a free-form Ansible module.
// In Ansible, a free-form module is called using a single scalar value
// instead of a key-value mapping.
//
// Example:
//
//	# Free-form
//	- command: echo "Hello"
//	  # IsFreeForm() -> true
//
//	# Structured
//	- ansible.builtin.yum:
//	    name: vim
//	    state: present
//	  # IsFreeForm() -> false
func (m *Module) IsFreeForm() bool {
	return m.Node.IsString()
}
