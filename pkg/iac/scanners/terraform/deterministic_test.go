package terraform

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/executor"
	parser2 "github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
	"github.com/stretchr/testify/require"
)

func Test_DeterministicResults(t *testing.T) {

	reg := rules.Register(badRule)
	defer rules.Deregister(reg)

	fs := testutil.CreateFS(t, map[string]string{
		"first.tf": `
resource "problem" "uhoh" {
	bad = true
	for_each = other.thing
}
		`,
		"second.tf": `
resource "other" "thing" {
	for_each = local.list
}
		`,
		"third.tf": `
locals {
	list = {
		a = 1,
		b = 2,
	}
}
		`,
	})

	for i := 0; i < 100; i++ {
		p := parser2.New(fs, "", parser2.OptionStopOnHCLError(true))
		err := p.ParseFS(context.TODO(), ".")
		require.NoError(t, err)
		modules, _, err := p.EvaluateAll(context.TODO())
		require.NoError(t, err)
		results, _, _ := executor.New().Execute(modules)
		require.Len(t, results.GetFailed(), 2)
	}
}
