package iamgo

import (
	"encoding/json"

	"github.com/liamg/jfather"
)

type Statement struct {
	inner innerStatement
	r     Range
}

type Statements struct {
	r     Range
	inner []Statement
}

type innerStatement struct {
	Sid          String     `json:"Sid,omitempty"`
	Effect       String     `json:"Effect"`
	Principal    Principals `json:"Principal,omitempty"`
	NotPrincipal Principals `json:"NotPrincipal,omitempty"`
	Action       Strings    `json:"Action,omitempty"`
	NotAction    Strings    `json:"NotAction,omitempty"`
	Resource     Strings    `json:"Resource,omitempty"`
	NotResource  Strings    `json:"NotResource,omitempty"`
	Condition    Conditions `json:"Condition,omitempty"`
}

func (s *Statements) UnmarshalJSONWithMetadata(node jfather.Node) error {
	s.r.StartLine = node.Range().Start.Line
	s.r.EndLine = node.Range().End.Line
	if err := node.Decode(&s.inner); err != nil {
		s.inner = append(s.inner, Statement{})
		return node.Decode(&s.inner[0])
	}
	return nil
}

func (s *Statement) UnmarshalJSONWithMetadata(node jfather.Node) error {
	s.r.StartLine = node.Range().Start.Line
	s.r.EndLine = node.Range().End.Line
	return node.Decode(&s.inner)
}

func (s Statements) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.inner)
}

func (s Statement) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.inner)
}

func (s *Statement) SID() (string, Range) {
	return s.inner.Sid.inner, s.inner.Sid.r
}

func (s *Statement) Effect() (string, Range) {
	return s.inner.Effect.inner, s.inner.Effect.r
}

func (s *Statement) Actions() ([]string, Range) {
	return s.inner.Action.inner, s.inner.Action.r
}

func (s *Statement) NotActions() ([]string, Range) {
	return s.inner.NotAction.inner, s.inner.NotAction.r
}

func (s *Statement) Resources() ([]string, Range) {
	return s.inner.Resource.inner, s.inner.Resource.r
}

func (s *Statement) NotResource() ([]string, Range) {
	return s.inner.NotResource.inner, s.inner.NotResource.r
}

func (s *Statement) Conditions() ([]Condition, Range) {
	return s.inner.Condition.inner, s.inner.Condition.r
}

func (s *Statement) Principals() (Principals, Range) {
	return s.inner.Principal, s.inner.Principal.r
}

func (s *Statement) NotPrincipals() (Principals, Range) {
	return s.inner.NotPrincipal, s.inner.NotPrincipal.r
}

func (s *Statement) Range() Range {
	return s.r
}
