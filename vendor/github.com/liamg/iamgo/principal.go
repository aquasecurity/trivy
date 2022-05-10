package iamgo

import (
	"encoding/json"

	"github.com/liamg/jfather"
)

type Principals struct {
	inner innerPrincipals
	r     Range
}

type innerPrincipals struct {
	All            Bool    `json:"-"`
	AWS            Strings `json:"AWS,omitempty"`
	CanonicalUsers Strings `json:"CanonicalUser,omitempty"`
	Federated      Strings `json:"Federated,omitempty"`
	Service        Strings `json:"Service,omitempty"`
}

func (p *Principals) All() (bool, Range) {
	return p.inner.All.inner, p.inner.All.r
}

func (p *Principals) AWS() ([]string, Range) {
	return p.inner.AWS.inner, p.inner.AWS.r
}

func (p *Principals) CanonicalUsers() ([]string, Range) {
	return p.inner.CanonicalUsers.inner, p.inner.CanonicalUsers.r
}

func (p *Principals) Federated() ([]string, Range) {
	return p.inner.Federated.inner, p.inner.Federated.r
}

func (p *Principals) Service() ([]string, Range) {
	return p.inner.Service.inner, p.inner.Service.r
}

func (p *Principals) UnmarshalJSONWithMetadata(node jfather.Node) error {
	p.r.StartLine = node.Range().Start.Line
	p.r.EndLine = node.Range().End.Line

	var str string
	if err := node.Decode(&str); err == nil {
		p.inner.All.inner = str == "*"
		p.inner.All.r = p.r
		return nil
	}

	return node.Decode(&p.inner)
}

func (p Principals) MarshalJSON() ([]byte, error) {
	if p.inner.All.inner {
		return []byte(`"*"`), nil
	}
	data := make(map[string]interface{})
	if len(p.inner.AWS.inner) > 0 {
		data["AWS"] = p.inner.AWS.inner
	}
	if len(p.inner.CanonicalUsers.inner) > 0 {
		data["CanonicalUsers"] = p.inner.CanonicalUsers.inner
	}
	if len(p.inner.Federated.inner) > 0 {
		data["Federated"] = p.inner.Federated.inner
	}
	if len(p.inner.Service.inner) > 0 {
		data["Service"] = p.inner.Service.inner
	}
	return json.Marshal(data)
}
