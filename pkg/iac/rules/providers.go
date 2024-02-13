package rules

import (
	"encoding/json"
	"strings"
)

type Provider struct {
	Name     string    `json:"name"`
	Services []Service `json:"services"`
}

type Service struct {
	Name   string  `json:"name"`
	Checks []Check `json:"checks"`
}

type Check struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func GetProvidersHierarchy() (providers map[string]map[string][]string) {

	registeredRules := GetRegistered()

	provs := make(map[string]map[string][]string)

	for _, rule := range registeredRules {

		cNames := make(map[string]bool)
		pName := strings.ToLower(rule.GetRule().Provider.DisplayName())
		sName := strings.ToLower(rule.GetRule().Service)
		cName := rule.GetRule().AVDID

		if _, ok := provs[pName]; !ok {
			provs[pName] = make(map[string][]string)
		}

		if _, ok := provs[pName][sName]; !ok {
			provs[pName][sName] = make([]string, 0)
		}

		if _, ok := cNames[cName]; !ok {
			cNames[cName] = true
			provs[pName][sName] = append(provs[pName][sName], cName)
		}
	}

	return provs
}

func GetProviders() (providers []Provider) {

	registeredRules := GetRegistered()

	provs := make(map[string]map[string][]Check)

	for _, rule := range registeredRules {

		pName := strings.ToLower(rule.GetRule().Provider.DisplayName())
		sName := strings.ToLower(rule.GetRule().Service)
		cName := rule.GetRule().AVDID
		desc := rule.GetRule().Summary

		if _, ok := provs[pName]; !ok {
			provs[pName] = make(map[string][]Check)
		}

		if _, ok := provs[pName][sName]; !ok {
			provs[pName][sName] = []Check{}
		}

		provs[pName][sName] = append(provs[pName][sName], Check{
			Name:        cName,
			Description: desc,
		})
	}

	for providerName, providerServices := range provs {
		var services []Service
		for serviceName, checks := range providerServices {
			services = append(services, Service{
				Name:   serviceName,
				Checks: checks,
			})
		}

		providers = append(providers, Provider{
			Name:     providerName,
			Services: services,
		})
	}

	return providers
}

func GetProvidersAsJson() ([]byte, error) {

	providers := GetProviders()

	return json.MarshalIndent(providers, "", "  ")
}

func GetProviderNames() []string {

	registeredRules := GetRegistered()

	providers := make(map[string]bool)

	for _, rule := range registeredRules {

		if _, ok := providers[rule.GetRule().Provider.DisplayName()]; !ok {
			providers[rule.GetRule().Provider.DisplayName()] = true
		}

	}

	var uniqueProviders []string
	for p := range providers {
		uniqueProviders = append(uniqueProviders, p)
	}

	return uniqueProviders

}

func GetProviderServiceNames(providerName string) []string {

	registeredRules := GetRegistered()

	services := make(map[string]bool)

	for _, rule := range registeredRules {

		if !strings.EqualFold(providerName, rule.GetRule().Provider.DisplayName()) {
			continue
		}

		if _, ok := services[rule.GetRule().Service]; !ok {
			services[rule.GetRule().Service] = true
		}

	}
	var uniqueServices []string
	for p := range services {
		uniqueServices = append(uniqueServices, p)
	}

	return uniqueServices
}

func GetProviderServiceCheckNames(providerName, serviceName string) []string {

	registeredRules := GetRegistered()

	var checks []string

	for _, rule := range registeredRules {

		if !strings.EqualFold(providerName, rule.GetRule().Provider.DisplayName()) ||
			!strings.EqualFold(serviceName, rule.GetRule().Service) {
			continue
		}

		checks = append(checks, rule.GetRule().AVDID)
	}
	return checks
}
