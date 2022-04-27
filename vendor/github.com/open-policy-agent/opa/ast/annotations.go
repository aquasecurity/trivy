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
		Location    *Location    `json:"location"`
		Path        Ref          `json:"path"`
		Annotations *Annotations `json:"annotations,omitempty"`
		node        Node
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

// Compare returns an integer indicating if s is less than, equal to, or greater
// than other.
func (a *Annotations) Compare(other *Annotations) int {

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

	for p, a := range as.byPackage {
		refs = append(refs, &AnnotationsRef{
			Location:    p.Location,
			Path:        p.Path,
			Annotations: a,
			node:        p,
		})
	}

	for r, as := range as.byRule {
		for _, a := range as {
			refs = append(refs, &AnnotationsRef{
				Location:    r.Location,
				Path:        r.Path(),
				Annotations: a,
				node:        r,
			})
		}
	}

	// Sort by path, then location, for stable output
	sort.SliceStable(refs, func(i, j int) bool {
		if refs[i].Path.Compare(refs[j].Path) < 0 {
			return true
		}
		if refs[i].Location.Compare(refs[j].Location) < 0 {
			return true
		}
		return false
	})

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
		refs = append(refs, &AnnotationsRef{
			Location:    a.Location,
			Path:        a.GetTargetPath(),
			Annotations: a,
			node:        a.node,
		})
	}
	for _, c := range t.Children {
		refs = c.flatten(refs)
	}
	return refs
}
