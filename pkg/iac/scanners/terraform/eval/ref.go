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
		if len(trav) < 2 {
			return nil
		}
		attr := trav[1].(hcl.TraverseAttr).Name
		return LocalAddr{Name: attr}
	case "var":
		if len(trav) < 2 {
			return nil
		}
		name := trav[1].(hcl.TraverseAttr).Name
		return VariableAddr{Name: name}
	case "module":
		if len(trav) < 2 {
			return nil
		}
		moduleCall := ModuleCallAddr{
			Name: trav[1].(hcl.TraverseAttr).Name,
		}
		remain := trav[2:]
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
		typ := trav[1].(hcl.TraverseAttr).Name
		name := trav[2].(hcl.TraverseAttr).Name
		return ResourceAddr{Mode: DataMode, Type: typ, Name: name}
	case "each":
		return ForEachAddr{Name: trav[1].(hcl.TraverseAttr).Name}
	case "count":
		return CountAddr{Name: trav[1].(hcl.TraverseAttr).Name}
	default:
		if len(trav) < 2 {
			return nil
		}
		typ := root
		name := trav[1].(hcl.TraverseAttr).Name
		return ResourceAddr{Mode: ManagedMode, Type: typ, Name: name}
	}
}
