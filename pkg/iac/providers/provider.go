package providers

import (
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Provider is the provider that the check applies to
type Provider string

const (
	UnknownProvider      Provider = ""
	AWSProvider          Provider = "aws"
	AzureProvider        Provider = "azure"
	CustomProvider       Provider = "custom"
	DigitalOceanProvider Provider = "digitalocean"
	GeneralProvider      Provider = "general"
	GitHubProvider       Provider = "github"
	GoogleProvider       Provider = "google"
	KubernetesProvider   Provider = "kubernetes"
	OracleProvider       Provider = "oracle"
	OpenStackProvider    Provider = "openstack"
	NifcloudProvider     Provider = "nifcloud"
	CloudStackProvider   Provider = "cloudstack"
)

func AllProviders() []Provider {
	return []Provider{
		AWSProvider, AzureProvider, DigitalOceanProvider, GitHubProvider, GoogleProvider,
		KubernetesProvider, OracleProvider, OpenStackProvider, NifcloudProvider, CloudStackProvider,
	}
}

func RuleProviderToString(provider Provider) string {
	return strings.ToUpper(string(provider))
}

func (p Provider) DisplayName() string {
	switch p {
	case "aws":
		return strings.ToUpper(string(p))
	case "digitalocean":
		return "Digital Ocean"
	case "github":
		return "GitHub"
	case "openstack":
		return "OpenStack"
	case "cloudstack":
		return "Cloudstack"
	default:
		return cases.Title(language.English).String(strings.ToLower(string(p)))
	}
}
func (p Provider) ConstName() string {
	return strings.ReplaceAll(p.DisplayName(), " ", "")
}
