package secret_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/secret"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

func TestMain(m *testing.M) {
	log.InitLogger(false, true)
	os.Exit(m.Run())
}

func TestSecretScanner(t *testing.T) {
	wantFinding1 := types.SecretFinding{
		RuleID:    "rule1",
		Category:  "general",
		Title:     "Generic Rule",
		Severity:  "HIGH",
		StartLine: 2,
		EndLine:   2,
		Match:     "generic secret line secret=\"*********\"",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "--- ignore block start ---",
					Highlighted: "--- ignore block start ---",
				},
				{
					Number:      2,
					Content:     "generic secret line secret=\"*********\"",
					Highlighted: "generic secret line secret=\"*********\"",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      3,
					Content:     "--- ignore block stop ---",
					Highlighted: "--- ignore block stop ---",
				},
			},
		},
	}
	wantFinding2 := types.SecretFinding{
		RuleID:    "rule1",
		Category:  "general",
		Title:     "Generic Rule",
		Severity:  "HIGH",
		StartLine: 4,
		EndLine:   4,
		Match:     "secret=\"**********\"",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      2,
					Content:     "generic secret line secret=\"*********\"",
					Highlighted: "generic secret line secret=\"*********\"",
				},
				{
					Number:      3,
					Content:     "--- ignore block stop ---",
					Highlighted: "--- ignore block stop ---",
				},
				{
					Number:      4,
					Content:     "secret=\"**********\"",
					Highlighted: "secret=\"**********\"",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      5,
					Content:     "credentials: { user: \"username\" password: \"123456789\" }",
					Highlighted: "credentials: { user: \"username\" password: \"123456789\" }",
				},
			},
		},
	}
	wantFindingRegexDisabled := types.SecretFinding{
		RuleID:    "rule1",
		Category:  "general",
		Title:     "Generic Rule",
		Severity:  "HIGH",
		StartLine: 4,
		EndLine:   4,
		Match:     "secret=\"**********\"",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      2,
					Content:     "generic secret line secret=\"somevalue\"",
					Highlighted: "generic secret line secret=\"somevalue\"",
				},
				{
					Number:      3,
					Content:     "--- ignore block stop ---",
					Highlighted: "--- ignore block stop ---",
				},
				{
					Number:      4,
					Content:     "secret=\"**********\"",
					Highlighted: "secret=\"**********\"",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      5,
					Content:     "credentials: { user: \"username\" password: \"123456789\" }",
					Highlighted: "credentials: { user: \"username\" password: \"123456789\" }",
				},
			},
		},
	}
	wantFinding3 := types.SecretFinding{
		RuleID:    "rule1",
		Category:  "general",
		Title:     "Generic Rule",
		Severity:  "HIGH",
		StartLine: 5,
		EndLine:   5,
		Match:     "credentials: { user: \"********\" password: \"*********\" }",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      3,
					Content:     "--- ignore block stop ---",
					Highlighted: "--- ignore block stop ---",
				},
				{
					Number:      4,
					Content:     "secret=\"othervalue\"",
					Highlighted: "secret=\"othervalue\"",
				},
				{
					Number:      5,
					Content:     "credentials: { user: \"********\" password: \"*********\" }",
					Highlighted: "credentials: { user: \"********\" password: \"*********\" }",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
			},
		},
	}
	wantFinding4 := types.SecretFinding{
		RuleID:    "rule1",
		Category:  "general",
		Title:     "Generic Rule",
		Severity:  "HIGH",
		StartLine: 5,
		EndLine:   5,
		Match:     "credentials: { user: \"********\" password: \"*********\" }",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      3,
					Content:     "--- ignore block stop ---",
					Highlighted: "--- ignore block stop ---",
				},
				{
					Number:      4,
					Content:     "secret=\"othervalue\"",
					Highlighted: "secret=\"othervalue\"",
				},
				{
					Number:      5,
					Content:     "credentials: { user: \"********\" password: \"*********\" }",
					Highlighted: "credentials: { user: \"********\" password: \"*********\" }",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
			},
		},
	}
	wantFinding5 := types.SecretFinding{
		RuleID:    "aws-access-key-id",
		Category:  secret.CategoryAWS,
		Title:     "AWS Access Key ID",
		Severity:  "CRITICAL",
		StartLine: 2,
		EndLine:   2,
		Match:     "AWS_ACCESS_KEY_ID=********************",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "'AWS_secret_KEY'=\"****************************************\"",
					Highlighted: "'AWS_secret_KEY'=\"****************************************\"",
				},
				{
					Number:      2,
					Content:     "AWS_ACCESS_KEY_ID=********************",
					Highlighted: "AWS_ACCESS_KEY_ID=********************",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      3,
					Content:     "\"aws_account_ID\":'1234-5678-9123'",
					Highlighted: "\"aws_account_ID\":'1234-5678-9123'",
				},
			},
		},
	}
	wantFinding5a := types.SecretFinding{
		RuleID:    "aws-access-key-id",
		Category:  secret.CategoryAWS,
		Title:     "AWS Access Key ID",
		Severity:  "CRITICAL",
		StartLine: 2,
		EndLine:   2,
		Match:     "AWS_ACCESS_KEY_ID=********************",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "GITHUB_PAT=****************************************",
					Highlighted: "GITHUB_PAT=****************************************",
				},
				{
					Number:      2,
					Content:     "AWS_ACCESS_KEY_ID=********************",
					Highlighted: "AWS_ACCESS_KEY_ID=********************",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
			},
		},
	}
	wantFindingPATDisabled := types.SecretFinding{
		RuleID:    "aws-access-key-id",
		Category:  secret.CategoryAWS,
		Title:     "AWS Access Key ID",
		Severity:  "CRITICAL",
		StartLine: 2,
		EndLine:   2,
		Match:     "AWS_ACCESS_KEY_ID=********************",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "GITHUB_PAT=ghp_012345678901234567890123456789abcdef",
					Highlighted: "GITHUB_PAT=ghp_012345678901234567890123456789abcdef",
				},
				{
					Number:      2,
					Content:     "AWS_ACCESS_KEY_ID=********************",
					Highlighted: "AWS_ACCESS_KEY_ID=********************",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
			},
		},
	}
	wantFinding6 := types.SecretFinding{
		RuleID:    "github-pat",
		Category:  secret.CategoryGitHub,
		Title:     "GitHub Personal Access Token",
		Severity:  "CRITICAL",
		StartLine: 1,
		EndLine:   1,
		Match:     "GITHUB_PAT=****************************************",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "GITHUB_PAT=****************************************",
					Highlighted: "GITHUB_PAT=****************************************",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      2,
					Content:     "AWS_ACCESS_KEY_ID=********************",
					Highlighted: "AWS_ACCESS_KEY_ID=********************",
				},
			},
		},
	}
	wantFindingGitHubPAT := types.SecretFinding{
		RuleID:    "github-fine-grained-pat",
		Category:  secret.CategoryGitHub,
		Title:     "GitHub Fine-grained personal access tokens",
		Severity:  "CRITICAL",
		StartLine: 1,
		EndLine:   1,
		Match:     "GITHUB_TOKEN=*********************************************************************************************",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "GITHUB_TOKEN=*********************************************************************************************",
					Highlighted: "GITHUB_TOKEN=*********************************************************************************************",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
			},
		},
	}
	wantFindingMyAwsAccessKey := types.SecretFinding{
		RuleID:    "aws-secret-access-key",
		Category:  secret.CategoryAWS,
		Title:     "AWS Secret Access Key",
		Severity:  "CRITICAL",
		StartLine: 1,
		EndLine:   1,
		Match:     `MyAWS_secret_KEY="****************************************"`,
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "MyAWS_secret_KEY=\"****************************************\"",
					Highlighted: "MyAWS_secret_KEY=\"****************************************\"",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      2,
					Content:     "our*********************************************************************************************",
					Highlighted: "our*********************************************************************************************",
				},
			},
		},
	}

	wantFindingMyGitHubPAT := types.SecretFinding{
		RuleID:    "github-fine-grained-pat",
		Category:  secret.CategoryGitHub,
		Title:     "GitHub Fine-grained personal access tokens",
		Severity:  "CRITICAL",
		StartLine: 2,
		EndLine:   2,
		Match:     "our*********************************************************************************************",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "MyAWS_secret_KEY=\"****************************************\"",
					Highlighted: "MyAWS_secret_KEY=\"****************************************\"",
				},
				{
					Number:      2,
					Content:     "our*********************************************************************************************",
					Highlighted: "our*********************************************************************************************",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
			},
		},
	}
	wantFindingGHButDisableAWS := types.SecretFinding{
		RuleID:    "github-pat",
		Category:  secret.CategoryGitHub,
		Title:     "GitHub Personal Access Token",
		Severity:  "CRITICAL",
		StartLine: 1,
		EndLine:   1,
		Match:     "GITHUB_PAT=****************************************",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "GITHUB_PAT=****************************************",
					Highlighted: "GITHUB_PAT=****************************************",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      2,
					Content:     "AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF",
					Highlighted: "AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF",
				},
			},
		},
	}
	wantFinding7 := types.SecretFinding{
		RuleID:    "github-pat",
		Category:  secret.CategoryGitHub,
		Title:     "GitHub Personal Access Token",
		Severity:  "CRITICAL",
		StartLine: 1,
		EndLine:   1,
		Match:     "aaaaaaaaaaaaaaaaaa GITHUB_PAT=**************************************** bbbbbbbbbbbbbbbbbbb",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "aaaaaaaaaaaaaaaaaa GITHUB_PAT=**************************************** bbbbbbbbbbbbbbbbbbb",
					Highlighted: "aaaaaaaaaaaaaaaaaa GITHUB_PAT=**************************************** bbbbbbbbbbbbbbbbbbb",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
			},
		},
	}
	wantFinding8 := types.SecretFinding{
		RuleID:    "rule1",
		Category:  "general",
		Title:     "Generic Rule",
		Severity:  "UNKNOWN",
		StartLine: 2,
		EndLine:   2,
		Match:     "generic secret line secret=\"*********\"",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "--- ignore block start ---",
					Highlighted: "--- ignore block start ---",
				},
				{
					Number:      2,
					Content:     "generic secret line secret=\"*********\"",
					Highlighted: "generic secret line secret=\"*********\"",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      3,
					Content:     "--- ignore block stop ---",
					Highlighted: "--- ignore block stop ---",
				},
			},
		},
	}
	wantFinding9 := types.SecretFinding{
		RuleID:    "aws-secret-access-key",
		Category:  secret.CategoryAWS,
		Title:     "AWS Secret Access Key",
		Severity:  "CRITICAL",
		StartLine: 1,
		EndLine:   1,
		Match:     `'AWS_secret_KEY'="****************************************"`,
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "'AWS_secret_KEY'=\"****************************************\"",
					Highlighted: "'AWS_secret_KEY'=\"****************************************\"",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      2,
					Content:     "AWS_ACCESS_KEY_ID=********************",
					Highlighted: "AWS_ACCESS_KEY_ID=********************",
				},
			},
		},
	}

	wantFinding10 := types.SecretFinding{
		RuleID:    "aws-secret-access-key",
		Category:  secret.CategoryAWS,
		Title:     "AWS Secret Access Key",
		Severity:  "CRITICAL",
		StartLine: 5,
		EndLine:   5,
		Match:     `  "created_by": "ENV aws_sec_key "****************************************",`,
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      3,
					Content:     "\"aws_account_ID\":'1234-5678-9123'",
					Highlighted: "\"aws_account_ID\":'1234-5678-9123'",
				},
				{
					Number:      4,
					Content:     "AWS_example=AKIAIOSFODNN7EXAMPLE",
					Highlighted: "AWS_example=AKIAIOSFODNN7EXAMPLE",
				},
				{
					Number:      5,
					Content:     "  \"created_by\": \"ENV aws_sec_key \"****************************************\",",
					Highlighted: "  \"created_by\": \"ENV aws_sec_key \"****************************************\",",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
			},
		},
	}
	wantFindingAsymmetricPrivateKeyJson := types.SecretFinding{
		RuleID:    "private-key",
		Category:  secret.CategoryAsymmetricPrivateKey,
		Title:     "Asymmetric Private Key",
		Severity:  "HIGH",
		StartLine: 1,
		EndLine:   1,
		Match:     "----BEGIN RSA PRIVATE KEY-----**************************************************************************************************************************-----END RSA PRIVATE",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "----BEGIN RSA PRIVATE KEY-----**************************************************************************************************************************-----END RSA PRIVATE",
					Highlighted: "----BEGIN RSA PRIVATE KEY-----**************************************************************************************************************************-----END RSA PRIVATE",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
			},
		},
	}
	wantFindingAsymmetricPrivateKey := types.SecretFinding{
		RuleID:    "private-key",
		Category:  secret.CategoryAsymmetricPrivateKey,
		Title:     "Asymmetric Private Key",
		Severity:  "HIGH",
		StartLine: 1,
		EndLine:   1,
		Match:     "----BEGIN RSA PRIVATE KEY-----****************************************************************************************************************************************************************************************-----END RSA PRIVATE",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "----BEGIN RSA PRIVATE KEY-----****************************************************************************************************************************************************************************************-----END RSA PRIVATE",
					Highlighted: "----BEGIN RSA PRIVATE KEY-----****************************************************************************************************************************************************************************************-----END RSA PRIVATE",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
			},
		},
	}
	wantFindingAsymmSecretKey := types.SecretFinding{
		RuleID:    "private-key",
		Category:  secret.CategoryAsymmetricPrivateKey,
		Title:     "Asymmetric Private Key",
		Severity:  "HIGH",
		StartLine: 1,
		EndLine:   1,
		Match:     "----BEGIN RSA PRIVATE KEY-----**************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************-----END RSA PRIVATE",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "----BEGIN RSA PRIVATE KEY-----**************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************-----END RSA PRIVATE",
					Highlighted: "----BEGIN RSA PRIVATE KEY-----**************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************-----END RSA PRIVATE",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      2,
					Content:     "",
					Highlighted: "",
					IsCause:     false,
					FirstCause:  false,
					LastCause:   false,
				},
			},
		},
	}
	wantFindingAlibabaAccessKeyId := types.SecretFinding{
		RuleID:    "alibaba-access-key-id",
		Category:  secret.CategoryAlibaba,
		Title:     "Alibaba AccessKey ID",
		Severity:  "HIGH",
		StartLine: 2,
		EndLine:   2,
		Match:     "key = ************************,",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "key : LTAI1234567890ABCDEFG123asd",
					Highlighted: "key : LTAI1234567890ABCDEFG123asd",
				},
				{
					Number:      2,
					Content:     "key = ************************,",
					Highlighted: "key = ************************,",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      3,
					Content:     "asdLTAI1234567890ABCDEFG123",
					Highlighted: "asdLTAI1234567890ABCDEFG123",
				},
			},
		},
	}
	wantFindingDockerKey1 := types.SecretFinding{
		RuleID:    "dockerconfig-secret",
		Category:  secret.CategoryDocker,
		Title:     "Dockerconfig secret exposed",
		Severity:  "HIGH",
		StartLine: 4,
		EndLine:   4,
		Match:     "  .dockercfg: ************",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      2,
					Content:     "  .dockerconfigjson: ************",
					Highlighted: "  .dockerconfigjson: ************",
				},
				{
					Number:      3,
					Content:     "data2:",
					Highlighted: "data2:",
				},
				{
					Number:      4,
					Content:     "  .dockercfg: ************",
					Highlighted: "  .dockercfg: ************",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
			},
		},
	}
	wantFindingDockerKey2 := types.SecretFinding{
		RuleID:    "dockerconfig-secret",
		Category:  secret.CategoryDocker,
		Title:     "Dockerconfig secret exposed",
		Severity:  "HIGH",
		StartLine: 2,
		EndLine:   2,
		Match:     "  .dockerconfigjson: ************",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "data1:",
					Highlighted: "data1:",
				},
				{
					Number:      2,
					Content:     "  .dockerconfigjson: ************",
					Highlighted: "  .dockerconfigjson: ************",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      3,
					Content:     "data2:",
					Highlighted: "data2:",
				},
			},
		},
	}
	wantFindingPrivatePackagistOrgReadToken := types.SecretFinding{
		RuleID:    "private-packagist-token",
		Category:  secret.CategoryPrivatePackagist,
		Title:     "Private Packagist token",
		Severity:  "HIGH",
		StartLine: 1,
		EndLine:   1,
		Match:     "ORG_READ_TOKEN=**********************************************************************************",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "ORG_READ_TOKEN=**********************************************************************************",
					Highlighted: "ORG_READ_TOKEN=**********************************************************************************",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      2,
					Content:     "ORG_WRITE_TOKEN=**********************************************************************************",
					Highlighted: "ORG_WRITE_TOKEN=**********************************************************************************",
					IsCause:     false,
					FirstCause:  false,
					LastCause:   false,
				},
			},
		},
	}
	wantFindingPrivatePackagistOrgUpdateToken := types.SecretFinding{
		RuleID:    "private-packagist-token",
		Category:  secret.CategoryPrivatePackagist,
		Title:     "Private Packagist token",
		Severity:  "HIGH",
		StartLine: 2,
		EndLine:   2,
		Match:     "ORG_WRITE_TOKEN=**********************************************************************************",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "ORG_READ_TOKEN=**********************************************************************************",
					Highlighted: "ORG_READ_TOKEN=**********************************************************************************",
					IsCause:     false,
					FirstCause:  false,
					LastCause:   false,
				},
				{
					Number:      2,
					Content:     "ORG_WRITE_TOKEN=**********************************************************************************",
					Highlighted: "ORG_WRITE_TOKEN=**********************************************************************************",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      3,
					Content:     "USER_TOKEN=**********************************************************************************",
					Highlighted: "USER_TOKEN=**********************************************************************************",
					IsCause:     false,
					FirstCause:  false,
					LastCause:   false,
				},
			},
		},
	}
	wantFindingPrivatePackagistUserToken := types.SecretFinding{
		RuleID:    "private-packagist-token",
		Category:  secret.CategoryPrivatePackagist,
		Title:     "Private Packagist token",
		Severity:  "HIGH",
		StartLine: 3,
		EndLine:   3,
		Match:     "USER_TOKEN=**********************************************************************************",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "ORG_READ_TOKEN=**********************************************************************************",
					Highlighted: "ORG_READ_TOKEN=**********************************************************************************",
					IsCause:     false,
					FirstCause:  false,
					LastCause:   false,
				},
				{
					Number:      2,
					Content:     "ORG_WRITE_TOKEN=**********************************************************************************",
					Highlighted: "ORG_WRITE_TOKEN=**********************************************************************************",
					IsCause:     false,
					FirstCause:  false,
					LastCause:   false,
				},
				{
					Number:      3,
					Content:     "USER_TOKEN=**********************************************************************************",
					Highlighted: "USER_TOKEN=**********************************************************************************",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      4,
					Content:     "",
					Highlighted: "",
					IsCause:     false,
					FirstCause:  false,
					LastCause:   false,
				},
			},
		},
	}
	wantFindingHuggingFace := types.SecretFinding{
		RuleID:    "hugging-face-access-token",
		Category:  secret.CategoryHuggingFace,
		Title:     "Hugging Face Access Token",
		Severity:  "CRITICAL",
		StartLine: 1,
		EndLine:   1,
		Match:     "HF_example_token: ******************************************",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "HF_example_token: ******************************************",
					Highlighted: "HF_example_token: ******************************************",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
			},
		},
	}

	wantFindingGrafanaQuoted := types.SecretFinding{
		RuleID:    "grafana-api-token",
		Category:  secret.CategoryGrafana,
		Title:     "Grafana API token",
		Severity:  "MEDIUM",
		StartLine: 1,
		EndLine:   1,
		Match:     "GRAFANA_TOKEN=**********************************************************************************************",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "GRAFANA_TOKEN=**********************************************************************************************",
					Highlighted: "GRAFANA_TOKEN=**********************************************************************************************",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      2,
					Content:     "GRAFANA_TOKEN=**************************************************************************************",
					Highlighted: "GRAFANA_TOKEN=**************************************************************************************",
					IsCause:     false,
					FirstCause:  false,
					LastCause:   false,
				},
			},
		},
	}

	wantFindingGrafanaUnquoted := types.SecretFinding{
		RuleID:    "grafana-api-token",
		Category:  secret.CategoryGrafana,
		Title:     "Grafana API token",
		Severity:  "MEDIUM",
		StartLine: 2,
		EndLine:   2,
		Match:     "GRAFANA_TOKEN=********************************************************************************************",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "GRAFANA_TOKEN=**************************************************************************************",
					Highlighted: "GRAFANA_TOKEN=**************************************************************************************",
					IsCause:     false,
					FirstCause:  false,
					LastCause:   false,
				},
				{
					Number:      2,
					Content:     "GRAFANA_TOKEN=********************************************************************************************",
					Highlighted: "GRAFANA_TOKEN=********************************************************************************************",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      3,
					Content:     "",
					Highlighted: "",
				},
			},
		},
	}

	wantMultiLine := types.SecretFinding{
		RuleID:    "multi-line-secret",
		Category:  "general",
		Title:     "Generic Rule",
		Severity:  "HIGH",
		StartLine: 2,
		EndLine:   2,
		Match:     "***************",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "123",
					Highlighted: "123",
				},
				{
					Number:      2,
					Content:     "***************",
					Highlighted: "***************",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      3,
					Content:     "123",
					Highlighted: "123",
				},
			},
		},
	}
	wantFindingTokenInsideJs := types.SecretFinding{
		RuleID:    "stripe-publishable-token",
		Category:  "Stripe",
		Title:     "Stripe Publishable Key",
		Severity:  "LOW",
		StartLine: 1,
		EndLine:   1,
		Match:     "){case a.ez.PRODUCTION:return\"********************************\";case a.ez.TEST:cas",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "){case a.ez.PRODUCTION:return\"********************************\";case a.ez.TEST:cas",
					Highlighted: "){case a.ez.PRODUCTION:return\"********************************\";case a.ez.TEST:cas",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
			},
		},
	}
	wantFindingJWT := types.SecretFinding{
		RuleID:    "jwt-token",
		Category:  "JWT",
		Title:     "JWT token",
		Severity:  "MEDIUM",
		StartLine: 3,
		EndLine:   3,
		Match:     "jwt: ***********************************************************************************************************************************************************",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "asd",
					Highlighted: "asd",
				},
				{
					Number:      2,
					Content:     "aaaa",
					Highlighted: "aaaa",
				},
				{
					Number:      3,
					Content:     "jwt: ***********************************************************************************************************************************************************",
					Highlighted: "jwt: ***********************************************************************************************************************************************************",
					IsCause:     true,
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      4,
					Content:     "asda",
					Highlighted: "asda",
				},
			},
		},
	}

	tests := []struct {
		name          string
		configPath    string
		inputFilePath string
		want          types.Secret
	}{
		{
			name:          "find match",
			configPath:    filepath.Join("testdata", "config.yaml"),
			inputFilePath: filepath.Join("testdata", "secret.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "secret.txt"),
				Findings: []types.SecretFinding{
					wantFinding1,
					wantFinding2,
				},
			},
		},
		{
			name:          "find aws secrets",
			configPath:    filepath.Join("testdata", "config.yaml"),
			inputFilePath: filepath.Join("testdata", "aws-secrets.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "aws-secrets.txt"),
				Findings: []types.SecretFinding{
					wantFinding5,
					wantFinding10,
					wantFinding9,
				},
			},
		},
		{
			name:          "find Asymmetric Private Key secrets",
			configPath:    filepath.Join("testdata", "skip-test.yaml"),
			inputFilePath: filepath.Join("testdata", "asymmetric-private-secret.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "asymmetric-private-secret.txt"),
				Findings: []types.SecretFinding{wantFindingAsymmetricPrivateKey},
			},
		},
		{
			name:          "find Alibaba AccessKey ID txt",
			configPath:    filepath.Join("testdata", "skip-test.yaml"),
			inputFilePath: "testdata/alibaba-access-key-id.txt",
			want: types.Secret{
				FilePath: "testdata/alibaba-access-key-id.txt",
				Findings: []types.SecretFinding{wantFindingAlibabaAccessKeyId},
			},
		},
		{
			name:          "find Asymmetric Private Key secrets json",
			configPath:    filepath.Join("testdata", "skip-test.yaml"),
			inputFilePath: filepath.Join("testdata", "asymmetric-private-secret.json"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "asymmetric-private-secret.json"),
				Findings: []types.SecretFinding{wantFindingAsymmetricPrivateKeyJson},
			},
		},
		{
			name:          "find Docker registry credentials",
			configPath:    filepath.Join("testdata", "skip-test.yaml"),
			inputFilePath: filepath.Join("testdata", "docker-secrets.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "docker-secrets.txt"),
				Findings: []types.SecretFinding{
					wantFindingDockerKey1,
					wantFindingDockerKey2,
				},
			},
		},
		{
			name:          "find Hugging face secret",
			configPath:    filepath.Join("testdata", "config.yaml"),
			inputFilePath: filepath.Join("testdata", "hugging-face-secret.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "hugging-face-secret.txt"),
				Findings: []types.SecretFinding{wantFindingHuggingFace},
			},
		},
		{
			name:          "find grafana secret",
			configPath:    filepath.Join("testdata", "config.yaml"),
			inputFilePath: filepath.Join("testdata", "grafana-env.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "grafana-env.txt"),
				Findings: []types.SecretFinding{wantFindingGrafanaUnquoted, wantFindingGrafanaQuoted},
			},
		},
		{
			name:          "find JWT token",
			configPath:    filepath.Join("testdata", "config.yaml"),
			inputFilePath: filepath.Join("testdata", "jwt-secret.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "jwt-secret.txt"),
				Findings: []types.SecretFinding{wantFindingJWT},
			},
		},
		{
			name:          "find Private Packagist tokens",
			configPath:    filepath.Join("testdata", "config.yaml"),
			inputFilePath: filepath.Join("testdata", "private-packagist.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "private-packagist.txt"),
				Findings: []types.SecretFinding{
					wantFindingPrivatePackagistOrgReadToken,
					wantFindingPrivatePackagistOrgUpdateToken,
					wantFindingPrivatePackagistUserToken,
				},
			},
		},
		{
			name:          "include when keyword found",
			configPath:    filepath.Join("testdata", "config-happy-keywords.yaml"),
			inputFilePath: filepath.Join("testdata", "secret.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "secret.txt"),
				Findings: []types.SecretFinding{
					wantFinding1,
					wantFinding2,
				},
			},
		},
		{
			name:          "exclude when no keyword found",
			configPath:    filepath.Join("testdata", "config-sad-keywords.yaml"),
			inputFilePath: filepath.Join("testdata", "secret.txt"),
			want:          types.Secret{},
		},
		{
			name:          "should ignore .md files by default",
			configPath:    filepath.Join("testdata", "config.yaml"),
			inputFilePath: filepath.Join("testdata", "secret.md"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "secret.md"),
			},
		},
		{
			name:          "should disable .md allow rule",
			configPath:    filepath.Join("testdata", "config-disable-allow-rule-md.yaml"),
			inputFilePath: filepath.Join("testdata", "secret.md"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "secret.md"),
				Findings: []types.SecretFinding{
					wantFinding1,
					wantFinding2,
				},
			},
		},
		{
			name:          "should find ghp builtin secret",
			configPath:    filepath.Join("testdata", "skip-test.yaml"),
			inputFilePath: filepath.Join("testdata", "builtin-rule-secret.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "builtin-rule-secret.txt"),
				Findings: []types.SecretFinding{
					wantFinding5a,
					wantFinding6,
				},
			},
		},
		{
			name:          "should find GitHub Personal Access Token (classic)",
			configPath:    filepath.Join("testdata", "skip-test.yaml"),
			inputFilePath: "testdata/github-token.txt",
			want: types.Secret{
				FilePath: "testdata/github-token.txt",
				Findings: []types.SecretFinding{wantFindingGitHubPAT},
			},
		},
		{
			name:          "should enable github-pat builtin rule, but disable aws-access-key-id rule",
			configPath:    filepath.Join("testdata", "config-enable-ghp.yaml"),
			inputFilePath: filepath.Join("testdata", "builtin-rule-secret.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "builtin-rule-secret.txt"),
				Findings: []types.SecretFinding{wantFindingGHButDisableAWS},
			},
		},
		{
			name:          "should disable github-pat builtin rule",
			configPath:    filepath.Join("testdata", "config-disable-ghp.yaml"),
			inputFilePath: filepath.Join("testdata", "builtin-rule-secret.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "builtin-rule-secret.txt"),
				Findings: []types.SecretFinding{wantFindingPATDisabled},
			},
		},
		{
			name:          "should disable custom rule",
			configPath:    filepath.Join("testdata", "config-disable-rule1.yaml"),
			inputFilePath: filepath.Join("testdata", "secret.txt"),
			want:          types.Secret{},
		},
		{
			name:          "allow-rule path",
			configPath:    filepath.Join("testdata", "allow-path.yaml"),
			inputFilePath: filepath.Join("testdata", "secret.txt"),
			want:          types.Secret{},
		},
		{
			name:          "allow-rule regex inside group",
			configPath:    filepath.Join("testdata", "allow-regex.yaml"),
			inputFilePath: filepath.Join("testdata", "secret.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "secret.txt"),
				Findings: []types.SecretFinding{wantFinding1},
			},
		},
		{
			name:          "allow-rule regex outside group",
			configPath:    filepath.Join("testdata", "allow-regex-outside-group.yaml"),
			inputFilePath: filepath.Join("testdata", "secret.txt"),
			want:          types.Secret{},
		},
		{
			name:          "exclude-block regexes",
			configPath:    filepath.Join("testdata", "exclude-block.yaml"),
			inputFilePath: filepath.Join("testdata", "secret.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "secret.txt"),
				Findings: []types.SecretFinding{wantFindingRegexDisabled},
			},
		},
		{
			name:          "skip examples file",
			configPath:    filepath.Join("testdata", "skip-test.yaml"),
			inputFilePath: filepath.Join("testdata", "example-secret.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "example-secret.txt"),
			},
		},
		{
			name:          "global allow-rule path",
			configPath:    filepath.Join("testdata", "global-allow-path.yaml"),
			inputFilePath: filepath.Join("testdata", "secret.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "secret.txt"),
				Findings: nil,
			},
		},
		{
			name:          "global allow-rule regex",
			configPath:    filepath.Join("testdata", "global-allow-regex.yaml"),
			inputFilePath: filepath.Join("testdata", "secret.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "secret.txt"),
				Findings: []types.SecretFinding{wantFinding1},
			},
		},
		{
			name:          "global exclude-block regexes",
			configPath:    filepath.Join("testdata", "global-exclude-block.yaml"),
			inputFilePath: filepath.Join("testdata", "secret.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "secret.txt"),
				Findings: []types.SecretFinding{wantFindingRegexDisabled},
			},
		},
		{
			name:          "multiple secret groups",
			configPath:    filepath.Join("testdata", "multiple-secret-groups.yaml"),
			inputFilePath: filepath.Join("testdata", "secret.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "secret.txt"),
				Findings: []types.SecretFinding{
					wantFinding3,
					wantFinding4,
				},
			},
		},
		{
			name:          "truncate long line",
			configPath:    filepath.Join("testdata", "skip-test.yaml"),
			inputFilePath: filepath.Join("testdata", "long-line-secret.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "long-line-secret.txt"),
				Findings: []types.SecretFinding{wantFinding7},
			},
		},
		{
			name:          "add unknown severity when rule has no severity",
			configPath:    filepath.Join("testdata", "config-without-severity.yaml"),
			inputFilePath: filepath.Join("testdata", "secret.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "secret.txt"),
				Findings: []types.SecretFinding{wantFinding8},
			},
		},
		{
			name:          "add unknown severity when rule has no severity",
			configPath:    filepath.Join("testdata", "config-with-incorrect-severity.yaml"),
			inputFilePath: filepath.Join("testdata", "secret.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "secret.txt"),
				Findings: []types.SecretFinding{wantFinding8},
			},
		},
		{
			name:          "update severity if rule severity is not in uppercase",
			configPath:    filepath.Join("testdata", "config-with-non-uppercase-severity.yaml"),
			inputFilePath: filepath.Join("testdata", "secret.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "secret.txt"),
				Findings: []types.SecretFinding{wantFinding8},
			},
		},
		{
			name:          "use unknown severity when rule has incorrect severity",
			configPath:    filepath.Join("testdata", "config-with-incorrect-severity.yaml"),
			inputFilePath: filepath.Join("testdata", "secret.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "secret.txt"),
				Findings: []types.SecretFinding{wantFinding8},
			},
		},
		{
			name:          "invalid aws secrets",
			configPath:    filepath.Join("testdata", "skip-test.yaml"),
			inputFilePath: filepath.Join("testdata", "invalid-aws-secrets.txt"),
			want:          types.Secret{},
		},
		{
			name:          "secret inside another word",
			configPath:    filepath.Join("testdata", "skip-test.yaml"),
			inputFilePath: filepath.Join("testdata", "wrapped-secrets.txt"),
			want:          types.Secret{},
		},
		{
			name:          "sensitive secret inside another word",
			configPath:    filepath.Join("testdata", "skip-test.yaml"),
			inputFilePath: filepath.Join("testdata", "wrapped-secrets-sensitive.txt"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "wrapped-secrets-sensitive.txt"),
				Findings: []types.SecretFinding{
					wantFindingMyAwsAccessKey,
					wantFindingMyGitHubPAT,
				},
			},
		},
		{
			name:          "asymmetric file",
			configPath:    filepath.Join("testdata", "skip-test.yaml"),
			inputFilePath: "testdata/asymmetric-private-key.txt",
			want: types.Secret{
				FilePath: "testdata/asymmetric-private-key.txt",
				Findings: []types.SecretFinding{wantFindingAsymmSecretKey},
			},
		},
		{
			name:          "begin/end line symbols without multi-line mode",
			configPath:    filepath.Join("testdata", "multi-line-off.yaml"),
			inputFilePath: "testdata/multi-line.txt",
			want:          types.Secret{},
		},
		{
			name:          "begin/end line symbols with multi-line mode",
			configPath:    filepath.Join("testdata", "multi-line-on.yaml"),
			inputFilePath: "testdata/multi-line.txt",
			want: types.Secret{
				FilePath: "testdata/multi-line.txt",
				Findings: []types.SecretFinding{wantMultiLine},
			},
		},
		{
			name:          "long obfuscated js code with secrets",
			configPath:    filepath.Join("testdata", "skip-test.yaml"),
			inputFilePath: filepath.Join("testdata", "obfuscated.js"),
			want: types.Secret{
				FilePath: filepath.Join("testdata", "obfuscated.js"),
				Findings: []types.SecretFinding{wantFindingTokenInsideJs},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, err := os.ReadFile(tt.inputFilePath)
			require.NoError(t, err)

			content = bytes.ReplaceAll(content, []byte("\r"), []byte(""))

			c, err := secret.ParseConfig(tt.configPath)
			require.NoError(t, err)

			s := secret.NewScanner(c)
			got := s.Scan(secret.ScanArgs{
				FilePath: tt.inputFilePath,
				Content:  content,
			},
			)
			assert.Equal(t, tt.want, got)
		})
	}
}
