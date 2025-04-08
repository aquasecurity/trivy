package scan

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

type CheckFunc func(s *state.State) (results Results)

type EngineMetadata struct {
	GoodExamples        []string `json:"good_examples,omitempty"`
	BadExamples         []string `json:"bad_examples,omitempty"`
	RemediationMarkdown string   `json:"remediation_markdown,omitempty"`
	Links               []string `json:"links,omitempty"`
}

type CustomChecks struct {
	Terraform *TerraformCustomCheck
}

type TerraformCustomCheck struct {
	RequiredTypes   []string
	RequiredLabels  []string
	RequiredSources []string
	Check           func(*terraform.Block, *terraform.Module) Results
}

type Rule struct {
	Deprecated     bool                             `json:"deprecated"`
	AVDID          string                           `json:"avd_id"`
	Aliases        []string                         `json:"aliases"`
	ShortCode      string                           `json:"short_code"`
	Summary        string                           `json:"summary"`
	Explanation    string                           `json:"explanation"`
	Impact         string                           `json:"impact"`
	Resolution     string                           `json:"resolution"`
	Provider       providers.Provider               `json:"provider"`
	Service        string                           `json:"service"`
	Links          []string                         `json:"links"`
	Severity       severity.Severity                `json:"severity"`
	Terraform      *EngineMetadata                  `json:"terraform,omitempty"`
	CloudFormation *EngineMetadata                  `json:"cloud_formation,omitempty"`
	Examples       string                           `json:"-"`
	CustomChecks   CustomChecks                     `json:"-"`
	RegoPackage    string                           `json:"-"`
	Frameworks     map[framework.Framework][]string `json:"frameworks"`
	Check          CheckFunc                        `json:"-"`
}

func (r Rule) IsDeprecated() bool {
	return r.Deprecated
}

func (r Rule) HasID(id string) bool {
	if r.AVDID == id || r.LongID() == id {
		return true
	}
	for _, alias := range r.Aliases {
		if alias == id {
			return true
		}
	}
	return false
}

func (r Rule) LongID() string {
	return strings.ToLower(fmt.Sprintf("%s-%s-%s", r.Provider, r.Service, r.ShortCode))
}

func (r Rule) ServiceDisplayName() string {
	return nicify(r.Service)
}

func (r Rule) ShortCodeDisplayName() string {
	return nicify(r.ShortCode)
}

var acronyms = []string{
	"acl",
	"alb",
	"api",
	"arn",
	"aws",
	"cidr",
	"db",
	"dns",
	"ebs",
	"ec2",
	"ecr",
	"ecs",
	"efs",
	"eks",
	"elb",
	"gke",
	"http",
	"http2",
	"https",
	"iam",
	"im",
	"imds",
	"ip",
	"ips",
	"kms",
	"lb",
	"md5",
	"mfa",
	"mq",
	"msk",
	"rbac",
	"rdp",
	"rds",
	"rsa",
	"sam",
	"sgr",
	"sha1",
	"sha256",
	"sns",
	"sql",
	"sqs",
	"ssh",
	"ssm",
	"tls",
	"ubla",
	"vm",
	"vpc",
	"vtpm",
	"waf",
}

var specials = map[string]string{
	"dynamodb":   "DynamoDB",
	"documentdb": "DocumentDB",
	"mysql":      "MySQL",
	"postgresql": "PostgreSQL",
	"acls":       "ACLs",
	"ips":        "IPs",
	"bigquery":   "BigQuery",
}

func nicify(input string) string {
	input = strings.ToLower(input)
	for replace, with := range specials {
		input = regexp.MustCompile(fmt.Sprintf("\\b%s\\b", replace)).ReplaceAllString(input, with)
	}
	for _, acronym := range acronyms {
		input = regexp.MustCompile(fmt.Sprintf("\\b%s\\b", acronym)).ReplaceAllString(input, strings.ToUpper(acronym))
	}
	return cases.Title(language.English).String(strings.ReplaceAll(input, "-", " "))
}
