package eval

import "github.com/hashicorp/hcl/v2"

type Ref struct {
	Addr Address
}

func exprReferences(expr hcl.Expression) []*Ref {
	return travReferences(expr.Variables())
}

func travReferences(traversals []hcl.Traversal) []*Ref {
	refs := make([]*Ref, 0, len(traversals))
	for _, trav := range traversals {
		if trav.IsRelative() {
			continue
		}
		addr := parseReference(trav)
		if addr != nil {
			refs = append(refs, &Ref{Addr: addr})
		}
	}
	return refs
}

func parseReference(trav hcl.Traversal) Address {
	root := trav.RootName()

	switch root {
	case "local":
		name, _, ok := parseSingleAttrReference(trav)
		if !ok {
			return nil
		}
		return LocalAddr{Name: name}
	case "var":
		name, _, ok := parseSingleAttrReference(trav)
		if !ok {
			return nil
		}
		return VariableAddr{Name: name}
	case "module":
		name, remain, ok := parseSingleAttrReference(trav)
		if !ok {
			return nil
		}

		moduleCall := ModuleCallAddr{
			Name: name,
		}

		if len(remain) == 0 {
			return moduleCall
		}

		if _, ok := remain[0].(hcl.TraverseIndex); ok {
			remain = remain[1:]
			if len(remain) == 0 {
				return moduleCall
			}
		}

		if attrTrav, ok := remain[0].(hcl.TraverseAttr); ok {
			return ModuleCallOutputAddr{Call: moduleCall, Name: attrTrav.Name}
		}
		return nil
	case "data":
		if len(trav) < 3 {
			return nil
		}
		typ, remain, ok := parseSingleAttrReference(trav)
		if !ok {
			return nil
		}
		name := remain[0].(hcl.TraverseAttr).Name
		return ResourceAddr{Mode: DataMode, Type: typ, Name: name}
	case "each":
		name, _, ok := parseSingleAttrReference(trav)
		if !ok {
			return nil
		}
		return ForEachAddr{Name: name}
	case "count":
		name, _, ok := parseSingleAttrReference(trav)
		if !ok {
			return nil
		}
		return CountAddr{Name: name}
	default:
		name, _, ok := parseSingleAttrReference(trav)
		if !ok {
			return nil
		}
		return ResourceAddr{Mode: ManagedMode, Type: root, Name: name}
	}
}

func parseSingleAttrReference(trav hcl.Traversal) (string, hcl.Traversal, bool) {
	if len(trav) < 2 {
		return "", nil, false
	}

	if _, ok := trav[0].(hcl.TraverseRoot); !ok {
		return "", nil, false
	}

	attr, ok := trav[1].(hcl.TraverseAttr)
	if !ok {
		return "", nil, false
	}
	return attr.Name, trav[2:], true
}
