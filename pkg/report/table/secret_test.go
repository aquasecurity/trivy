package table_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report/table"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestSecretRenderer(t *testing.T) {
	tests := []struct {
		name  string
		input types.Result
		want  string
	}{
		{
			name: "single line",
			input: types.Result{
				Target: "my-file",
				Secrets: []types.DetectedSecret{
					{
						RuleID:    "rule-id",
						Category:  ftypes.SecretRuleCategory("category"),
						Title:     "this is a title",
						Severity:  "HIGH",
						Layer:     ftypes.Layer{DiffID: "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203"},
						StartLine: 1,
						EndLine:   1,
						Code: ftypes.Code{
							Lines: []ftypes.Line{
								{
									Number:     1,
									Content:    "password=secret",
									IsCause:    true,
									FirstCause: true,
									LastCause:  true,
								},
							},
						},
						Match: "secret",
					},
				},
			},
			want: `
my-file (secrets)
=================
Total: 1 (MEDIUM: 0, HIGH: 1)

HIGH: category (rule-id)
════════════════════════════════════════
this is a title
────────────────────────────────────────
 my-file:1 (added in layer 'beee9f30bc1f')
────────────────────────────────────────
   1 [ password=secret
────────────────────────────────────────


`,
		},
		{
			name: "multiple line",
			input: types.Result{
				Target: "my-file",
				Secrets: []types.DetectedSecret{
					{
						RuleID:   "rule-id",
						Category: ftypes.SecretRuleCategory("category"),
						Title:    "this is a title",
						Severity: "HIGH",
						Layer: ftypes.Layer{
							DiffID:    "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
							CreatedBy: "COPY my-file my-file",
						},
						StartLine: 3,
						EndLine:   4,
						Code: ftypes.Code{
							Lines: []ftypes.Line{
								{
									Number:  1,
									Content: "#!/bin/bash",
								},
								{
									Number:  2,
									Content: "",
								},
								{
									Number:     3,
									Content:    "password=this is a \\",
									IsCause:    true,
									FirstCause: true,
								},
								{
									Number:    4,
									Content:   "secret password",
									IsCause:   true,
									LastCause: true,
								},
								{
									Number:  5,
									Content: "some-app --password $password",
								},
								{
									Number:  6,
									Content: "echo all done",
								},
							},
						},
						Match: "secret",
					},
				},
			},
			want: `
my-file (secrets)
=================
Total: 1 (MEDIUM: 0, HIGH: 1)

HIGH: category (rule-id)
════════════════════════════════════════
this is a title
────────────────────────────────────────
 my-file:3-4 (added by 'COPY my-file my-file')
────────────────────────────────────────
   1   #!/bin/bash
   2   
   3 ┌ password=this is a \
   4 └ secret password
   5   some-app --password $password
   6   echo all done
────────────────────────────────────────


`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := bytes.NewBuffer([]byte{})
			renderer := table.NewSecretRenderer(buf, false, []dbTypes.Severity{
				dbTypes.SeverityHigh,
				dbTypes.SeverityMedium,
			})
			renderer.Render(tt.input)
			assert.Equal(t, tt.want, strings.ReplaceAll(buf.String(), "\r\n", "\n"))
		})
	}
}
