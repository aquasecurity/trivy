package iamgo

import (
	"encoding/json"

	"github.com/liamg/jfather"
)

type Document struct {
	inner innerDocument
	r     Range
}

type innerDocument struct {
	Version   String     `json:"Version"`
	Id        String     `json:"Id,omitempty"`
	Statement Statements `json:"Statement"`
}

func (d *Document) UnmarshalJSONWithMetadata(node jfather.Node) error {
	d.r.StartLine = node.Range().Start.Line
	d.r.EndLine = node.Range().End.Line
	return node.Decode(&d.inner)
}

func (d *Document) Version() (string, Range) {
	return d.inner.Version.inner, d.inner.Version.r
}

func (d *Document) ID() (string, Range) {
	return d.inner.Id.inner, d.inner.Id.r
}

func (d *Document) Statements() ([]Statement, Range) {
	return d.inner.Statement.inner, d.inner.Statement.r
}

func (d *Document) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.inner)
}
