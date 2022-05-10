package iamgo

type PolicyBuilder struct {
	doc Document
}

func NewPolicyBuilder() *PolicyBuilder {
	return &PolicyBuilder{}
}

func PolicyBuilderFromDocument(doc Document) *PolicyBuilder {
	return &PolicyBuilder{
		doc: doc,
	}
}

func (p *PolicyBuilder) Build() Document {
	return p.doc
}

func (p *PolicyBuilder) WithVersion(version string, lines ...int) *PolicyBuilder {
	p.doc.inner.Version.inner = version
	if len(lines) > 0 {
		p.doc.inner.Version.r.StartLine = lines[0]
	}
	if len(lines) > 1 {
		p.doc.inner.Version.r.EndLine = lines[1]
	}
	return p
}

func (p *PolicyBuilder) WithId(id string, lines ...int) *PolicyBuilder {
	p.doc.inner.Id.inner = id
	if len(lines) > 0 {
		p.doc.inner.Id.r.StartLine = lines[0]
	}
	if len(lines) > 1 {
		p.doc.inner.Id.r.EndLine = lines[1]
	}
	return p
}

func (p *PolicyBuilder) WithStatement(s Statement, lines ...int) *PolicyBuilder {

	for i, existing := range p.doc.inner.Statement.inner {
		if existing.inner.Sid == s.inner.Sid {
			p.doc.inner.Statement.inner[i] = s
			if len(lines) > 0 {
				p.doc.inner.Statement.r.StartLine = lines[0]
			}
			if len(lines) > 1 {
				p.doc.inner.Statement.r.EndLine = lines[1]
			}
			return p
		}
	}

	p.doc.inner.Statement.inner = append(p.doc.inner.Statement.inner, s)
	if len(lines) > 0 {
		p.doc.inner.Statement.r.StartLine = lines[0]
	}
	if len(lines) > 1 {
		p.doc.inner.Statement.r.EndLine = lines[1]
	}
	return p
}

type StatementBuilder struct {
	stmt Statement
}

func NewStatementBuilder() *StatementBuilder {
	return &StatementBuilder{}
}

func (s *StatementBuilder) Build() Statement {
	return s.stmt
}

func (s *StatementBuilder) WithRange(start, end int) *StatementBuilder {
	s.stmt.r = Range{
		StartLine: start,
		EndLine:   end,
	}
	return s
}

func (s *StatementBuilder) WithSid(sid string, lines ...int) *StatementBuilder {
	s.stmt.inner.Sid.inner = sid
	if len(lines) > 0 {
		s.stmt.inner.Sid.r.StartLine = lines[0]
	}
	if len(lines) > 1 {
		s.stmt.inner.Sid.r.EndLine = lines[1]
	}
	return s
}

func (s *StatementBuilder) WithEffect(effect string, lines ...int) *StatementBuilder {
	s.stmt.inner.Effect.inner = effect
	if len(lines) > 0 {
		s.stmt.inner.Effect.r.StartLine = lines[0]
	}
	if len(lines) > 1 {
		s.stmt.inner.Effect.r.EndLine = lines[1]
	}
	return s
}

func (s *StatementBuilder) WithActions(actions []string, lines ...int) *StatementBuilder {
	s.stmt.inner.Action.inner = actions
	if len(lines) > 0 {
		s.stmt.inner.Action.r.StartLine = lines[0]
	}
	if len(lines) > 1 {
		s.stmt.inner.Action.r.EndLine = lines[1]
	}
	return s
}

func (s *StatementBuilder) WithNotActions(actions []string, lines ...int) *StatementBuilder {
	s.stmt.inner.NotAction.inner = actions
	if len(lines) > 0 {
		s.stmt.inner.NotAction.r.StartLine = lines[0]
	}
	if len(lines) > 1 {
		s.stmt.inner.NotAction.r.EndLine = lines[1]
	}
	return s
}

func (s *StatementBuilder) WithResources(resources []string, lines ...int) *StatementBuilder {
	s.stmt.inner.Resource.inner = resources
	if len(lines) > 0 {
		s.stmt.inner.Resource.r.StartLine = lines[0]
	}
	if len(lines) > 1 {
		s.stmt.inner.Resource.r.EndLine = lines[1]
	}
	return s
}

func (s *StatementBuilder) WithNotResources(resources []string, lines ...int) *StatementBuilder {
	s.stmt.inner.NotResource.inner = resources
	if len(lines) > 0 {
		s.stmt.inner.NotResource.r.StartLine = lines[0]
	}
	if len(lines) > 1 {
		s.stmt.inner.NotResource.r.EndLine = lines[1]
	}
	return s
}

func (s *StatementBuilder) WithAllPrincipals(all bool, lines ...int) *StatementBuilder {
	s.stmt.inner.Principal.inner.All.inner = all
	if len(lines) > 0 {
		s.stmt.inner.Principal.inner.All.r.StartLine = lines[0]
		if lines[0] < s.stmt.inner.Principal.r.StartLine || s.stmt.inner.Principal.r.StartLine == 0 {
			s.stmt.inner.Principal.r.StartLine = lines[0]
		}
	}
	if len(lines) > 1 {
		s.stmt.inner.Principal.inner.All.r.EndLine = lines[1]
		if lines[1] > s.stmt.inner.Principal.r.EndLine {
			s.stmt.inner.Principal.r.EndLine = lines[1]
		}
	}
	return s
}

func (s *StatementBuilder) WithAWSPrincipals(aws []string, lines ...int) *StatementBuilder {
	s.stmt.inner.Principal.inner.AWS.inner = aws
	if len(lines) > 0 {
		s.stmt.inner.Principal.inner.AWS.r.StartLine = lines[0]
		if lines[0] < s.stmt.inner.Principal.r.StartLine || s.stmt.inner.Principal.r.StartLine == 0 {
			s.stmt.inner.Principal.r.StartLine = lines[0]
		}
	}
	if len(lines) > 1 {
		s.stmt.inner.Principal.inner.AWS.r.EndLine = lines[1]
		if lines[1] > s.stmt.inner.Principal.r.EndLine {
			s.stmt.inner.Principal.r.EndLine = lines[1]
		}
	}
	return s
}

func (s *StatementBuilder) WithCanonicalUsersPrincipals(cu []string, lines ...int) *StatementBuilder {
	s.stmt.inner.Principal.inner.CanonicalUsers.inner = cu
	if len(lines) > 0 {
		s.stmt.inner.Principal.inner.CanonicalUsers.r.StartLine = lines[0]
		if lines[0] < s.stmt.inner.Principal.r.StartLine || s.stmt.inner.Principal.r.StartLine == 0 {
			s.stmt.inner.Principal.r.StartLine = lines[0]
		}
	}
	if len(lines) > 1 {
		s.stmt.inner.Principal.inner.CanonicalUsers.r.EndLine = lines[1]
		if lines[1] > s.stmt.inner.Principal.r.EndLine {
			s.stmt.inner.Principal.r.EndLine = lines[1]
		}
	}
	return s
}

func (s *StatementBuilder) WithFederatedPrincipals(federated []string, lines ...int) *StatementBuilder {
	s.stmt.inner.Principal.inner.Federated.inner = federated
	if len(lines) > 0 {
		s.stmt.inner.Principal.inner.Federated.r.StartLine = lines[0]
		if lines[0] < s.stmt.inner.Principal.r.StartLine || s.stmt.inner.Principal.r.StartLine == 0 {
			s.stmt.inner.Principal.r.StartLine = lines[0]
		}
	}
	if len(lines) > 1 {
		s.stmt.inner.Principal.inner.Federated.r.EndLine = lines[1]
		if lines[1] > s.stmt.inner.Principal.r.EndLine {
			s.stmt.inner.Principal.r.EndLine = lines[1]
		}
	}
	return s
}

func (s *StatementBuilder) WithServicePrincipals(service []string, lines ...int) *StatementBuilder {
	s.stmt.inner.Principal.inner.Service.inner = service
	if len(lines) > 0 {
		s.stmt.inner.Principal.inner.Service.r.StartLine = lines[0]
		if lines[0] < s.stmt.inner.Principal.r.StartLine || s.stmt.inner.Principal.r.StartLine == 0 {
			s.stmt.inner.Principal.r.StartLine = lines[0]
		}
	}
	if len(lines) > 1 {
		s.stmt.inner.Principal.inner.Service.r.EndLine = lines[1]
		if lines[1] > s.stmt.inner.Principal.r.EndLine {
			s.stmt.inner.Principal.r.EndLine = lines[1]
		}
	}
	return s
}

func (s *StatementBuilder) WithNotAllPrincipals(all bool, lines ...int) *StatementBuilder {
	s.stmt.inner.NotPrincipal.inner.All.inner = all
	if len(lines) > 0 {
		s.stmt.inner.NotPrincipal.inner.All.r.StartLine = lines[0]
		if lines[0] < s.stmt.inner.NotPrincipal.r.StartLine || s.stmt.inner.NotPrincipal.r.StartLine == 0 {
			s.stmt.inner.NotPrincipal.r.StartLine = lines[0]
		}
	}
	if len(lines) > 1 {
		s.stmt.inner.NotPrincipal.inner.All.r.EndLine = lines[1]
		if lines[1] > s.stmt.inner.NotPrincipal.r.EndLine {
			s.stmt.inner.NotPrincipal.r.EndLine = lines[1]
		}
	}
	return s
}

func (s *StatementBuilder) WithNotAWSPrincipals(aws []string, lines ...int) *StatementBuilder {
	s.stmt.inner.NotPrincipal.inner.AWS.inner = aws
	if len(lines) > 0 {
		s.stmt.inner.NotPrincipal.inner.AWS.r.StartLine = lines[0]
		if lines[0] < s.stmt.inner.NotPrincipal.r.StartLine || s.stmt.inner.NotPrincipal.r.StartLine == 0 {
			s.stmt.inner.NotPrincipal.r.StartLine = lines[0]
		}
	}
	if len(lines) > 1 {
		s.stmt.inner.NotPrincipal.inner.AWS.r.EndLine = lines[1]
		if lines[1] > s.stmt.inner.NotPrincipal.r.EndLine {
			s.stmt.inner.NotPrincipal.r.EndLine = lines[1]
		}
	}
	return s
}

func (s *StatementBuilder) WithNotCanonicalUsersPrincipals(cu []string, lines ...int) *StatementBuilder {
	s.stmt.inner.NotPrincipal.inner.CanonicalUsers.inner = cu
	if len(lines) > 0 {
		s.stmt.inner.NotPrincipal.inner.CanonicalUsers.r.StartLine = lines[0]
		if lines[0] < s.stmt.inner.NotPrincipal.r.StartLine || s.stmt.inner.NotPrincipal.r.StartLine == 0 {
			s.stmt.inner.NotPrincipal.r.StartLine = lines[0]
		}
	}
	if len(lines) > 1 {
		s.stmt.inner.NotPrincipal.inner.CanonicalUsers.r.EndLine = lines[1]
		if lines[1] > s.stmt.inner.NotPrincipal.r.EndLine {
			s.stmt.inner.NotPrincipal.r.EndLine = lines[1]
		}
	}
	return s
}

func (s *StatementBuilder) WithNotFederatedPrincipals(federated []string, lines ...int) *StatementBuilder {
	s.stmt.inner.NotPrincipal.inner.Federated.inner = federated
	if len(lines) > 0 {
		s.stmt.inner.NotPrincipal.inner.Federated.r.StartLine = lines[0]
		if lines[0] < s.stmt.inner.NotPrincipal.r.StartLine || s.stmt.inner.NotPrincipal.r.StartLine == 0 {
			s.stmt.inner.NotPrincipal.r.StartLine = lines[0]
		}
	}
	if len(lines) > 1 {
		s.stmt.inner.NotPrincipal.inner.Federated.r.EndLine = lines[1]
		if lines[1] > s.stmt.inner.NotPrincipal.r.EndLine {
			s.stmt.inner.NotPrincipal.r.EndLine = lines[1]
		}
	}
	return s
}

func (s *StatementBuilder) WithNotServicePrincipals(service []string, lines ...int) *StatementBuilder {
	s.stmt.inner.NotPrincipal.inner.Service.inner = service
	if len(lines) > 0 {
		s.stmt.inner.NotPrincipal.inner.Service.r.StartLine = lines[0]
		if lines[0] < s.stmt.inner.NotPrincipal.r.StartLine || s.stmt.inner.NotPrincipal.r.StartLine == 0 {
			s.stmt.inner.NotPrincipal.r.StartLine = lines[0]
		}
	}
	if len(lines) > 1 {
		s.stmt.inner.NotPrincipal.inner.Service.r.EndLine = lines[1]
		if lines[1] > s.stmt.inner.NotPrincipal.r.EndLine {
			s.stmt.inner.NotPrincipal.r.EndLine = lines[1]
		}
	}
	return s
}

func (s *StatementBuilder) WithCondition(operator string, key string, value []string, lines ...int) *StatementBuilder {
	var propRange Range

	r := s.stmt.inner.Condition.r
	if len(lines) > 0 {
		propRange.StartLine = lines[0]
		if lines[0] < r.StartLine || r.StartLine == 0 {
			r.StartLine = lines[0]
		}
	}
	if len(lines) > 1 {
		propRange.EndLine = lines[1]
		if lines[1] > r.EndLine || r.EndLine == 0 {
			r.EndLine = lines[1]
		}
	}
	s.stmt.inner.Condition.r = r
	s.stmt.inner.Condition.inner = append(s.stmt.inner.Condition.inner, Condition{
		operator: String{
			inner: operator,
			r:     propRange,
		},
		key: String{
			inner: key,
			r:     propRange,
		},
		value: Strings{
			inner: value,
			r:     propRange,
		},
	})
	return s
}
