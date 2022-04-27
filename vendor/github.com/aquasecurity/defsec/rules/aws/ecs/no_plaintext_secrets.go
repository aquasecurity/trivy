package ecs

import (
	"encoding/json"
	"fmt"

	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/security"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
	"github.com/owenrumney/squealer/pkg/squealer"
)

var CheckNoPlaintextSecrets = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0036",
		Provider:    providers.AWSProvider,
		Service:     "ecs",
		ShortCode:   "no-plaintext-secrets",
		Summary:     "Task definition defines sensitive environment variable(s).",
		Impact:      "Sensitive data could be exposed in the AWS Management Console",
		Resolution:  "Use secrets for the task definition",
		Explanation: `You should not make secrets available to a user in plaintext in any scenario. Secrets can instead be pulled from a secure secret storage system by the service requiring them.`,
		Links: []string{
			"https://docs.aws.amazon.com/systems-manager/latest/userguide/integration-ps-secretsmanager.html",
			"https://www.vaultproject.io/",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoPlaintextSecretsGoodExamples,
			BadExamples:         terraformNoPlaintextSecretsBadExamples,
			Links:               terraformNoPlaintextSecretsLinks,
			RemediationMarkdown: terraformNoPlaintextSecretsRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationNoPlaintextSecretsGoodExamples,
			BadExamples:         cloudFormationNoPlaintextSecretsBadExamples,
			Links:               cloudFormationNoPlaintextSecretsLinks,
			RemediationMarkdown: cloudFormationNoPlaintextSecretsRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {

		scanner := squealer.NewStringScanner()

		for _, definition := range s.AWS.ECS.TaskDefinitions {
			vars, err := readEnvVarsFromContainerDefinitions(definition.ContainerDefinitions.Value())
			if err != nil {
				continue
			}
			for key, val := range vars {
				if result := scanner.Scan(val); result.TransgressionFound || security.IsSensitiveAttribute(key) {
					results.Add(
						fmt.Sprintf("Container definition contains a potentially sensitive environment variable '%s': %s", key, result.Description),
						definition.ContainerDefinitions,
					)
				} else {
					results.AddPassed(&definition)
				}
			}
		}
		return
	},
)

type definition struct {
	EnvVars []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"environment"`
}

func readEnvVarsFromContainerDefinitions(raw string) (map[string]string, error) {

	var definitions []definition
	if err := json.Unmarshal([]byte(raw), &definitions); err != nil {
		return nil, err
	}

	envVars := make(map[string]string)
	for _, definition := range definitions {
		for _, env := range definition.EnvVars {
			envVars[env.Name] = env.Value
		}
	}

	return envVars, nil
}
