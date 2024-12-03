package iam

import (
	"github.com/liamg/iamgo"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type IAM struct {
	PasswordPolicy     PasswordPolicy
	Policies           []Policy
	Groups             []Group
	Users              []User
	Roles              []Role
	ServerCertificates []ServerCertificate
}

type ServerCertificate struct {
	Metadata   iacTypes.Metadata
	Expiration iacTypes.TimeValue
}

type Policy struct {
	Metadata iacTypes.Metadata
	Name     iacTypes.StringValue
	Document Document
	Builtin  iacTypes.BoolValue
}

type Document struct {
	Metadata iacTypes.Metadata
	Parsed   iamgo.Document
	IsOffset bool
	HasRefs  bool
}

func (d Document) ToRego() any {
	m := d.Metadata
	doc, _ := d.Parsed.MarshalJSON()
	input := map[string]any{
		"filepath":     m.Range().GetFilename(),
		"startline":    m.Range().GetStartLine(),
		"endline":      m.Range().GetEndLine(),
		"managed":      m.IsManaged(),
		"explicit":     m.IsExplicit(),
		"value":        string(doc),
		"sourceprefix": m.Range().GetSourcePrefix(),
		"fskey":        iacTypes.CreateFSKey(m.Range().GetFS()),
		"resource":     m.Reference(),
	}

	if m.Parent() != nil {
		input["parent"] = m.Parent().ToRego()
	}

	return input
}

type Group struct {
	Metadata iacTypes.Metadata
	Name     iacTypes.StringValue
	Policies []Policy
}

type User struct {
	Metadata   iacTypes.Metadata
	Name       iacTypes.StringValue
	Policies   []Policy
	AccessKeys []AccessKey
	MFADevices []MFADevice
	LastAccess iacTypes.TimeValue
}

func (u *User) HasLoggedIn() bool {
	return u.LastAccess.GetMetadata().IsResolvable() && !u.LastAccess.IsNever()
}

type MFADevice struct {
	Metadata  iacTypes.Metadata
	IsVirtual iacTypes.BoolValue
}

type AccessKey struct {
	Metadata     iacTypes.Metadata
	AccessKeyId  iacTypes.StringValue
	Active       iacTypes.BoolValue
	CreationDate iacTypes.TimeValue
	LastAccess   iacTypes.TimeValue
}

type Role struct {
	Metadata iacTypes.Metadata
	Name     iacTypes.StringValue
	Policies []Policy
}

func (d Document) MetadataFromIamGo(r ...iamgo.Range) iacTypes.Metadata {
	m := d.Metadata
	if d.HasRefs {
		return m
	}
	newRange := m.Range()
	var start int
	if !d.IsOffset {
		start = newRange.GetStartLine()
	}
	for _, rng := range r {
		newRange := iacTypes.NewRange(
			newRange.GetLocalFilename(),
			start+rng.StartLine,
			start+rng.EndLine,
			newRange.GetSourcePrefix(),
			newRange.GetFS(),
		)
		m = iacTypes.NewMetadata(newRange, m.Reference()).WithParent(m)
	}
	return m
}
