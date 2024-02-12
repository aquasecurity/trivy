package iam

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/liamg/iamgo"
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
	Metadata   defsecTypes.Metadata
	Expiration defsecTypes.TimeValue
}

type Policy struct {
	Metadata defsecTypes.Metadata
	Name     defsecTypes.StringValue
	Document Document
	Builtin  defsecTypes.BoolValue
}

type Document struct {
	Metadata defsecTypes.Metadata
	Parsed   iamgo.Document
	IsOffset bool
	HasRefs  bool
}

func (d Document) ToRego() interface{} {
	m := d.Metadata
	doc, _ := d.Parsed.MarshalJSON()
	input := map[string]interface{}{
		"filepath":     m.Range().GetFilename(),
		"startline":    m.Range().GetStartLine(),
		"endline":      m.Range().GetEndLine(),
		"managed":      m.IsManaged(),
		"explicit":     m.IsExplicit(),
		"value":        string(doc),
		"sourceprefix": m.Range().GetSourcePrefix(),
		"fskey":        defsecTypes.CreateFSKey(m.Range().GetFS()),
		"resource":     m.Reference(),
	}

	if m.Parent() != nil {
		input["parent"] = m.Parent().ToRego()
	}

	return input
}

type Group struct {
	Metadata defsecTypes.Metadata
	Name     defsecTypes.StringValue
	Users    []User
	Policies []Policy
}

type User struct {
	Metadata   defsecTypes.Metadata
	Name       defsecTypes.StringValue
	Groups     []Group
	Policies   []Policy
	AccessKeys []AccessKey
	MFADevices []MFADevice
	LastAccess defsecTypes.TimeValue
}

func (u *User) HasLoggedIn() bool {
	return u.LastAccess.GetMetadata().IsResolvable() && !u.LastAccess.IsNever()
}

type MFADevice struct {
	Metadata  defsecTypes.Metadata
	IsVirtual defsecTypes.BoolValue
}

type AccessKey struct {
	Metadata     defsecTypes.Metadata
	AccessKeyId  defsecTypes.StringValue
	Active       defsecTypes.BoolValue
	CreationDate defsecTypes.TimeValue
	LastAccess   defsecTypes.TimeValue
}

type Role struct {
	Metadata defsecTypes.Metadata
	Name     defsecTypes.StringValue
	Policies []Policy
}

func (d Document) MetadataFromIamGo(r ...iamgo.Range) defsecTypes.Metadata {
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
		newRange := defsecTypes.NewRange(
			newRange.GetLocalFilename(),
			start+rng.StartLine,
			start+rng.EndLine,
			newRange.GetSourcePrefix(),
			newRange.GetFS(),
		)
		m = defsecTypes.NewMetadata(newRange, m.Reference()).WithParent(m)
	}
	return m
}
