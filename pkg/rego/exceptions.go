package rego

import (
	"context"
	"fmt"
)

func (s *Scanner) isIgnored(ctx context.Context, namespace string, ruleName string, input interface{}) (bool, error) {
	if ignored, err := s.isNamespaceIgnored(ctx, namespace, input); err != nil {
		return false, err
	} else if ignored {
		return true, nil
	}
	return s.isRuleIgnored(ctx, namespace, ruleName, input)
}

func (s *Scanner) isNamespaceIgnored(ctx context.Context, namespace string, input interface{}) (bool, error) {
	exceptionQuery := fmt.Sprintf("data.namespace.exceptions.exception[_] == %q", namespace)
	result, _, err := s.runQuery(ctx, exceptionQuery, input, true)
	if err != nil {
		return false, fmt.Errorf("query namespace exceptions: %w", err)
	}
	return result.Allowed(), nil
}

func (s *Scanner) isRuleIgnored(ctx context.Context, namespace string, ruleName string, input interface{}) (bool, error) {
	exceptionQuery := fmt.Sprintf("endswith(%q, data.%s.exception[_][_])", ruleName, namespace)
	result, _, err := s.runQuery(ctx, exceptionQuery, input, true)
	if err != nil {
		return false, err
	}
	return result.Allowed(), nil
}
