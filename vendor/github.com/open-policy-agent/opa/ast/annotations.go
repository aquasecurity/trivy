// Copyright 2022 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ast

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/internal/deepcopy"
	"github.com/open-policy-agent/opa/util"
)

const (
	annotationScopePackage     = "package"
	annotationScopeImport      = "import"
	annotationScopeRule        = "rule"
	annotationScopeDocument    = "document"
	annotationScopeSubpackages = "subpackages"
)

type (
	// Annotations represents metadata attached to other AST nodes such as rules.
	Annotations struct {
		Location         *Location                    `json:"-"`
		Scope            string                       `json:"scope"`
		Title            string                       `json:"title,omitempty"`
		Description      string                       `json:"description,omitempty"`
		Organizations    []string                     `json:"organizations,omitempty"`
		RelatedResources []*RelatedResourceAnnotation `json:"related_resources,omitempty"`
		Authors          []*AuthorAnnotation          `json:"authors,omitempty"`
		Schemas          []*SchemaAnnotation          `json:"schemas,omitempty"`
		Custom           map[string]interface{}       `json:"custom,omitempty"`
		node             Node
	}

	// SchemaAnnotation contains a schema declaration for the document identified by the path.
	SchemaAnnotation struct {
		Path       Ref          `json:"path"`
		Schema     Ref          `json:"schema,omitempty"`
		Definition *interface{} `json:"definition,omitempty"`
	}

	AuthorAnnotation struct {
		Name  string `json:"name"`
		Email string `json:"email,omitempty"`
	}

	RelatedResourceAnnotation struct {
		Ref         url.URL `json:"ref"`
		Description string  `json:"description,omitempty"`
	}

	AnnotationSet struct {
		byRule    map[*Rule][]*Annotations
		byPackage map[*Package]*Annotations
		byPath    *annotationTreeNode
		modules   []*Module // Modules this set was constructed from
	}

	annotationTreeNode struct {
		Value    *Annotations
		Children map[Value]*annotationTreeNode // we assume key elements are hashable (vars and strings only!)
	}

	AnnotationsRef struct {
		Location    *Location    `json:"location"` // The location of the node the annotations are applied to
		Path        Ref          `json:"path"`     // The path of the node the annotations are applied to
		Annotations *Annotations `json:"annotations,omitempty"`
		node        Node         // The node the annotations are applied to
	}
)

func (a *Annotations) String() string {
	bs, _ := json.Marshal(a)
	return string(bs)
}

// Loc returns the location of this annotation.
func (a *Annotations) Loc() *Location {
	return a.Location
}

// SetLoc updates the location of this annotation.
func (a *Annotations) SetLoc(l *Location) {
	a.Location = l
}

// Compare returns an integer indicating if a is less than, equal to, or greater
// than other.
func (a *Annotations) Compare(other *Annotations) int {

	if a == nil && other == nil {
		return 0
	}

	if a == nil {
		return -1
	}

	if other == nil {
		return 1
	}

	if cmp := scopeCompare(a.Scope, other.Scope); cmp != 0 {
		return cmp
	}

	if cmp := strings.Compare(a.Title, other.Title); cmp != 0 {
		return cmp
	}

	if cmp := strings.Compare(a.Description, other.Description); cmp != 0 {
		return cmp
	}

	if cmp := compareStringLists(a.Organizations, other.Organizations); cmp != 0 {
		return cmp
	}

	if cmp := compareRelatedResources(a.RelatedResources, other.RelatedResources); cmp != 0 {
		return cmp
	}

	if cmp := compareAuthors(a.Authors, other.Authors); cmp != 0 {
		return cmp
	}

	if cmp := compareSchemas(a.Schemas, other.Schemas); cmp != 0 {
		return cmp
	}

	if cmp := util.Compare(a.Custom, other.Custom); cmp != 0 {
		return cmp
	}

	return 0
}

// GetTargetPath returns the path of the node these Annotations are applied to (the target)
func (a *Annotations) GetTargetPath() Ref {
	switch n := a.node.(type) {
	case *Package:
		return n.Path
	case *Rule:
		return n.Path()
	default:
		return nil
	}
}

func NewAnnotationsRef(a *Annotations) *AnnotationsRef {
	return &AnnotationsRef{
		Location:    a.node.Loc(),
		Path:        a.GetTargetPath(),
		Annotations: a,
		node:        a.node,
	}
}

func (ar *AnnotationsRef) GetPackage() *Package {
	switch n := ar.node.(type) {
	case *Package:
		return n
	case *Rule:
		return n.Module.Package
	default:
		return nil
	}
}

func (ar *AnnotationsRef) GetRule() *Rule {
	switch n := ar.node.(type) {
	case *Rule:
		return n
	default:
		return nil
	}
}

func scopeCompare(s1, s2 string) int {

	o1 := scopeOrder(s1)
	o2 := scopeOrder(s2)

	if o2 < o1 {
		return 1
	} else if o2 > o1 {
		return -1
	}

	if s1 < s2 {
		return -1
	} else if s2 < s1 {
		return 1
	}

	return 0
}

func scopeOrder(s string) int {
	switch s {
	case annotationScopeRule:
		return 1
	}
	return 0
}

func compareAuthors(a, b []*AuthorAnnotation) int {
	if len(a) > len(b) {
		return 1
	} else if len(a) < len(b) {
		return -1
	}

	for i := 0; i < len(a); i++ {
		if cmp := a[i].Compare(b[i]); cmp != 0 {
			return cmp
		}
	}

	return 0
}

func compareRelatedResources(a, b []*RelatedResourceAnnotation) int {
	if len(a) > len(b) {
		return 1
	} else if len(a) < len(b) {
		return -1
	}

	for i := 0; i < len(a); i++ {
		if cmp := strings.Compare(a[i].String(), b[i].String()); cmp != 0 {
			return cmp
		}
	}

	return 0
}

func compareSchemas(a, b []*SchemaAnnotation) int {
	max := len(a)
	if len(b) < max {
		max = len(b)
	}

	for i := 0; i < max; i++ {
		if cmp := a[i].Compare(b[i]); cmp != 0 {
			return cmp
		}
	}

	if len(a) > len(b) {
		return 1
	} else if len(a) < len(b) {
		return -1
	}

	return 0
}

func compareStringLists(a, b []string) int {
	if len(a) > len(b) {
		return 1
	} else if len(a) < len(b) {
		return -1
	}

	for i := 0; i < len(a); i++ {
		if cmp := strings.Compare(a[i], b[i]); cmp != 0 {
			return cmp
		}
	}

	return 0
}

// Copy returns a deep copy of s.
func (a *Annotations) Copy(node Node) *Annotations {
	cpy := *a

	cpy.Organizations = make([]string, len(a.Organizations))
	copy(cpy.Organizations, a.Organizations)

	cpy.RelatedResources = make([]*RelatedResourceAnnotation, len(a.RelatedResources))
	for i := range a.RelatedResources {
		cpy.RelatedResources[i] = a.RelatedResources[i].Copy()
	}

	cpy.Authors = make([]*AuthorAnnotation, len(a.Authors))
	for i := range a.Authors {
		cpy.Authors[i] = a.Authors[i].Copy()
	}

	cpy.Schemas = make([]*SchemaAnnotation, len(a.Schemas))
	for i := range a.Schemas {
		cpy.Schemas[i] = a.Schemas[i].Copy()
	}

	cpy.Custom = deepcopy.Map(a.Custom)

	cpy.node = node

	return &cpy
}

// toObject constructs an AST Object from a.
func (a *Annotations) toObject() (*Object, *Error) {
	obj := NewObject()

	if a == nil {
		return &obj, nil
	}

	if len(a.Scope) > 0 {
		obj.Insert(StringTerm("scope"), StringTerm(a.Scope))
	}

	if len(a.Title) > 0 {
		obj.Insert(StringTerm("title"), StringTerm(a.Title))
	}

	if len(a.Description) > 0 {
		obj.Insert(StringTerm("description"), StringTerm(a.Description))
	}

	if len(a.Organizations) > 0 {
		orgs := make([]*Term, 0, len(a.Organizations))
		for _, org := range a.Organizations {
			orgs = append(orgs, StringTerm(org))
		}
		obj.Insert(StringTerm("organizations"), ArrayTerm(orgs...))
	}

	if len(a.RelatedResources) > 0 {
		rrs := make([]*Term, 0, len(a.RelatedResources))
		for _, rr := range a.RelatedResources {
			rrObj := NewObject(Item(StringTerm("ref"), StringTerm(rr.Ref.String())))
			if len(rr.Description) > 0 {
				rrObj.Insert(StringTerm("description"), StringTerm(rr.Description))
			}
			rrs = append(rrs, NewTerm(rrObj))
		}
		obj.Insert(StringTerm("related_resources"), ArrayTerm(rrs...))
	}

	if len(a.Authors) > 0 {
		as := make([]*Term, 0, len(a.Authors))
		for _, author := range a.Authors {
			aObj := NewObject()
			if len(author.Name) > 0 {
				aObj.Insert(StringTerm("name"), StringTerm(author.Name))
			}
			if len(author.Email) > 0 {
				aObj.Insert(StringTerm("email"), StringTerm(author.Email))
			}
			as = append(as, NewTerm(aObj))
		}
		obj.Insert(StringTerm("authors"), ArrayTerm(as...))
	}

	if len(a.Schemas) > 0 {
		ss := make([]*Term, 0, len(a.Schemas))
		for _, s := range a.Schemas {
			sObj := NewObject()
			if len(s.Path) > 0 {
				sObj.Insert(StringTerm("path"), NewTerm(s.Path.toArray()))
			}
			if len(s.Schema) > 0 {
				sObj.Insert(StringTerm("schema"), NewTerm(s.Schema.toArray()))
			}
			if s.Definition != nil {
				def, err := InterfaceToValue(s.Definition)
				if err != nil {
					return nil, NewError(CompileErr, a.Location, "invalid definition in schema annotation: %s", err.Error())
				}
				sObj.Insert(StringTerm("definition"), NewTerm(def))
			}
			ss = append(ss, NewTerm(sObj))
		}
		obj.Insert(StringTerm("schemas"), ArrayTerm(ss...))
	}

	if len(a.Custom) > 0 {
		c, err := InterfaceToValue(a.Custom)
		if err != nil {
			return nil, NewError(CompileErr, a.Location, "invalid custom annotation %s", err.Error())
		}
		obj.Insert(StringTerm("custom"), NewTerm(c))
	}

	return &obj, nil
}

func attachAnnotationsNodes(mod *Module) Errors {
	var errs Errors

	// Find first non-annotation statement following each annotation and attach
	// the annotation to that statement.
	for _, a := range mod.Annotations {
		for _, stmt := range mod.stmts {
			_, ok := stmt.(*Annotations)
			if !ok {
				if stmt.Loc().Row > a.Location.Row {
					a.node = stmt
					break
				}
			}
		}

		if a.Scope == "" {
			switch a.node.(type) {
			case *Rule:
				a.Scope = annotationScopeRule
			case *Package:
				a.Scope = annotationScopePackage
			case *Import:
				a.Scope = annotationScopeImport
			}
		}

		if err := validateAnnotationScopeAttachment(a); err != nil {
			errs = append(errs, err)
		}
	}

	return errs
}

func validateAnnotationScopeAttachment(a *Annotations) *Error {

	switch a.Scope {
	case annotationScopeRule, annotationScopeDocument:
		if _, ok := a.node.(*Rule); ok {
			return nil
		}
		return newScopeAttachmentErr(a, "rule")
	case annotationScopePackage, annotationScopeSubpackages:
		if _, ok := a.node.(*Package); ok {
			return nil
		}
		return newScopeAttachmentErr(a, "package")
	}

	return NewError(ParseErr, a.Loc(), "invalid annotation scope '%v'", a.Scope)
}

// Copy returns a deep copy of a.
func (a *AuthorAnnotation) Copy() *AuthorAnnotation {
	cpy := *a
	return &cpy
}

// Compare returns an integer indicating if s is less than, equal to, or greater
// than other.
func (a *AuthorAnnotation) Compare(other *AuthorAnnotation) int {
	if cmp := strings.Compare(a.Name, other.Name); cmp != 0 {
		return cmp
	}

	if cmp := strings.Compare(a.Email, other.Email); cmp != 0 {
		return cmp
	}

	return 0
}

func (a *AuthorAnnotation) String() string {
	if len(a.Email) == 0 {
		return a.Name
	} else if len(a.Name) == 0 {
		return fmt.Sprintf("<%s>", a.Email)
	} else {
		return fmt.Sprintf("%s <%s>", a.Name, a.Email)
	}
}

// Copy returns a deep copy of rr.
func (rr *RelatedResourceAnnotation) Copy() *RelatedResourceAnnotation {
	cpy := *rr
	return &cpy
}

// Compare returns an integer indicating if s is less than, equal to, or greater
// than other.
func (rr *RelatedResourceAnnotation) Compare(other *RelatedResourceAnnotation) int {
	if cmp := strings.Compare(rr.Description, other.Description); cmp != 0 {
		return cmp
	}

	if cmp := strings.Compare(rr.Ref.String(), other.Ref.String()); cmp != 0 {
		return cmp
	}

	return 0
}

func (rr *RelatedResourceAnnotation) String() string {
	bs, _ := json.Marshal(rr)
	return string(bs)
}

func (rr *RelatedResourceAnnotation) MarshalJSON() ([]byte, error) {
	d := map[string]interface{}{
		"ref": rr.Ref.String(),
	}

	if len(rr.Description) > 0 {
		d["description"] = rr.Description
	}

	return json.Marshal(d)
}

// Copy returns a deep copy of s.
func (s *SchemaAnnotation) Copy() *SchemaAnnotation {
	cpy := *s
	return &cpy
}

// Compare returns an integer indicating if s is less than, equal to, or greater
// than other.
func (s *SchemaAnnotation) Compare(other *SchemaAnnotation) int {

	if cmp := s.Path.Compare(other.Path); cmp != 0 {
		return cmp
	}

	if cmp := s.Schema.Compare(other.Schema); cmp != 0 {
		return cmp
	}

	if s.Definition != nil && other.Definition == nil {
		return -1
	} else if s.Definition == nil && other.Definition != nil {
		return 1
	} else if s.Definition != nil && other.Definition != nil {
		return util.Compare(*s.Definition, *other.Definition)
	}

	return 0
}

func (s *SchemaAnnotation) String() string {
	bs, _ := json.Marshal(s)
	return string(bs)
}

func newAnnotationSet() *AnnotationSet {
	return &AnnotationSet{
		byRule:    map[*Rule][]*Annotations{},
		byPackage: map[*Package]*Annotations{},
		byPath:    newAnnotationTree(),
	}
}

func BuildAnnotationSet(modules []*Module) (*AnnotationSet, Errors) {
	as := newAnnotationSet()
	var errs Errors
	for _, m := range modules {
		for _, a := range m.Annotations {
			if err := as.add(a); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if len(errs) > 0 {
		return nil, errs
	}
	as.modules = modules
	return as, nil
}

func (as *AnnotationSet) add(a *Annotations) *Error {
	switch a.Scope {
	case annotationScopeRule:
		rule := a.node.(*Rule)
		as.byRule[rule] = append(as.byRule[rule], a)
	case annotationScopePackage:
		pkg := a.node.(*Package)
		if exist, ok := as.byPackage[pkg]; ok {
			return errAnnotationRedeclared(a, exist.Location)
		}
		as.byPackage[pkg] = a
	case annotationScopeDocument:
		rule := a.node.(*Rule)
		path := rule.Path()
		x := as.byPath.get(path)
		if x != nil {
			return errAnnotationRedeclared(a, x.Value.Location)
		}
		as.byPath.insert(path, a)
	case annotationScopeSubpackages:
		pkg := a.node.(*Package)
		x := as.byPath.get(pkg.Path)
		if x != nil && x.Value != nil {
			return errAnnotationRedeclared(a, x.Value.Location)
		}
		as.byPath.insert(pkg.Path, a)
	}
	return nil
}

func (as *AnnotationSet) GetRuleScope(r *Rule) []*Annotations {
	if as == nil {
		return nil
	}
	return as.byRule[r]
}

func (as *AnnotationSet) GetSubpackagesScope(path Ref) []*Annotations {
	if as == nil {
		return nil
	}
	return as.byPath.ancestors(path)
}

func (as *AnnotationSet) GetDocumentScope(path Ref) *Annotations {
	if as == nil {
		return nil
	}
	if node := as.byPath.get(path); node != nil {
		return node.Value
	}
	return nil
}

func (as *AnnotationSet) GetPackageScope(pkg *Package) *Annotations {
	if as == nil {
		return nil
	}
	return as.byPackage[pkg]
}

// Flatten returns a flattened list view of this AnnotationSet.
// The returned slice is sorted, first by the annotations' target path, then by their target location
func (as *AnnotationSet) Flatten() []*AnnotationsRef {
	var refs []*AnnotationsRef

	refs = as.byPath.flatten(refs)

	for _, a := range as.byPackage {
		refs = append(refs, NewAnnotationsRef(a))
	}

	for _, as := range as.byRule {
		for _, a := range as {
			refs = append(refs, NewAnnotationsRef(a))
		}
	}

	// Sort by path, then annotation location, for stable output
	sort.SliceStable(refs, func(i, j int) bool {
		if refs[i].Path.Compare(refs[j].Path) < 0 {
			return true
		}
		if refs[i].Annotations.Location.Compare(refs[j].Annotations.Location) < 0 {
			return true
		}
		return false
	})

	return refs
}

// Chain returns the chain of annotations leading up to the given rule.
// The returned slice is ordered as follows
// 0. Entries for the given rule, ordered from the METADATA block declared immediately above the rule, to the block declared farthest away (always at least one entry)
// 1. The 'document' scope entry, if any
// 2. The 'package' scope entry, if any
// 3. Entries for the 'subpackages' scope, if any; ordered from the closest package path to the fartest. E.g.: 'do.re.mi', 'do.re', 'do'
// The returned slice is guaranteed to always contain at least one entry, corresponding to the given rule.
func (as *AnnotationSet) Chain(rule *Rule) []*AnnotationsRef {
	var refs []*AnnotationsRef

	ruleAnnots := as.GetRuleScope(rule)

	if len(ruleAnnots) >= 1 {
		for _, a := range ruleAnnots {
			refs = append(refs, NewAnnotationsRef(a))
		}
	} else {
		// Make sure there is always a leading entry representing the passed rule, even if it has no annotations
		refs = append(refs, &AnnotationsRef{
			Location: rule.Location,
			Path:     rule.Path(),
			node:     rule,
		})
	}

	if len(refs) > 1 {
		// Sort by annotation location; chain must start with annotations declared closest to rule, then going outward
		sort.SliceStable(refs, func(i, j int) bool {
			return refs[i].Annotations.Location.Compare(refs[j].Annotations.Location) > 0
		})
	}

	docAnnots := as.GetDocumentScope(rule.Path())
	if docAnnots != nil {
		refs = append(refs, NewAnnotationsRef(docAnnots))
	}

	pkg := rule.Module.Package
	pkgAnnots := as.GetPackageScope(pkg)
	if pkgAnnots != nil {
		refs = append(refs, NewAnnotationsRef(pkgAnnots))
	}

	subPkgAnnots := as.GetSubpackagesScope(pkg.Path)
	// We need to reverse the order, as subPkgAnnots ordering will start at the root,
	// whereas we want to end at the root.
	for i := len(subPkgAnnots) - 1; i >= 0; i-- {
		refs = append(refs, NewAnnotationsRef(subPkgAnnots[i]))
	}

	return refs
}

func newAnnotationTree() *annotationTreeNode {
	return &annotationTreeNode{
		Value:    nil,
		Children: map[Value]*annotationTreeNode{},
	}
}

func (t *annotationTreeNode) insert(path Ref, value *Annotations) {
	node := t
	for _, k := range path {
		child, ok := node.Children[k.Value]
		if !ok {
			child = newAnnotationTree()
			node.Children[k.Value] = child
		}
		node = child
	}
	node.Value = value
}

func (t *annotationTreeNode) get(path Ref) *annotationTreeNode {
	node := t
	for _, k := range path {
		if node == nil {
			return nil
		}
		child, ok := node.Children[k.Value]
		if !ok {
			return nil
		}
		node = child
	}
	return node
}

// ancestors returns a slice of annotations in ascending order, starting with the root of ref; e.g.: 'root', 'root.foo', 'root.foo.bar'.
func (t *annotationTreeNode) ancestors(path Ref) (result []*Annotations) {
	node := t
	for _, k := range path {
		if node == nil {
			return result
		}
		child, ok := node.Children[k.Value]
		if !ok {
			return result
		}
		if child.Value != nil {
			result = append(result, child.Value)
		}
		node = child
	}
	return result
}

func (t *annotationTreeNode) flatten(refs []*AnnotationsRef) []*AnnotationsRef {
	if a := t.Value; a != nil {
		refs = append(refs, NewAnnotationsRef(a))
	}
	for _, c := range t.Children {
		refs = c.flatten(refs)
	}
	return refs
}
