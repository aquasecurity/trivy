package parser

import (
	"crypto/md5" //#nosec
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/liamg/memoryfs"

	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/log"
)

type Parser struct {
	logger *log.Logger
}

func New() *Parser {
	return &Parser{
		logger: log.WithPrefix("tfjson parser"),
	}
}

func (p *Parser) ParseFile(filepath string) (*PlanFile, error) {

	if _, err := os.Stat(filepath); err != nil {
		return nil, err
	}

	reader, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return p.Parse(reader)
}

func (p *Parser) Parse(reader io.Reader) (*PlanFile, error) {

	var planFile PlanFile

	if err := json.NewDecoder(reader).Decode(&planFile); err != nil {
		return nil, err
	}

	return &planFile, nil

}

func (p *PlanFile) ToFS() (*memoryfs.FS, error) {

	rootFS := memoryfs.New()

	var fileResources []string

	resources, err := getResources(p.PlannedValues.RootModule, p.ResourceChanges, p.Configuration)
	if err != nil {
		return nil, err
	}

	for _, r := range resources {
		fileResources = append(fileResources, r.ToHCL())
	}

	fileContent := strings.Join(fileResources, "\n\n")
	if err := rootFS.WriteFile("main.tf", []byte(fileContent), os.ModePerm); err != nil {
		return nil, err
	}
	return rootFS, nil

}

func getResources(module Module, resourceChanges []ResourceChange, configuration Configuration) ([]terraform.PlanBlock, error) {
	var resources []terraform.PlanBlock
	for _, r := range module.Resources {
		resourceName := r.Name
		if strings.HasPrefix(r.Address, "module.") {
			hashable := strings.TrimSuffix(strings.Split(r.Address, fmt.Sprintf(".%s.", r.Type))[0], ".data")
			/* #nosec */
			hash := fmt.Sprintf("%x", md5.Sum([]byte(hashable)))
			resourceName = fmt.Sprintf("%s_%s", r.Name, hash)
		}

		res := terraform.NewPlanBlock(r.Mode, r.Type, resourceName)

		changes := getValues(r.Address, resourceChanges)
		// process the changes to get the after state
		for k, v := range changes.After {
			switch t := v.(type) {
			case []any:
				if len(t) == 0 {
					continue
				}
				val := t[0]
				switch v := val.(type) {
				// is it a HCL block?
				case map[string]any:
					res.Blocks[k] = v
				// just a normal attribute then
				default:
					res.Attributes[k] = v
				}
			default:
				res.Attributes[k] = v
			}
		}

		resourceConfig := getConfiguration(r.Address, configuration.RootModule)
		if resourceConfig != nil {

			for attr, val := range resourceConfig.Expressions {
				if value, shouldReplace := unpackConfigurationValue(val, r); shouldReplace || !res.HasAttribute(attr) {
					res.Attributes[attr] = value
				}
			}
		}
		resources = append(resources, *res)
	}

	for _, m := range module.ChildModules {
		cr, err := getResources(m.Module, resourceChanges, configuration)
		if err != nil {
			return nil, err
		}
		resources = append(resources, cr...)
	}

	return resources, nil
}

func unpackConfigurationValue(val any, r Resource) (any, bool) {
	if t, ok := val.(map[string]any); ok {
		for k, v := range t {
			switch k {
			case "references":
				reference := v.([]any)[0].(string)
				if strings.HasPrefix(r.Address, "module.") {
					hashable := strings.TrimSuffix(strings.Split(r.Address, fmt.Sprintf(".%s.", r.Type))[0], ".data")
					/* #nosec */
					hash := fmt.Sprintf("%x", md5.Sum([]byte(hashable)))

					parts := strings.Split(reference, ".")
					var rejoin []string

					name := parts[1]
					remainder := parts[2:]
					if parts[0] == "data" {
						rejoin = append(rejoin, parts[:2]...)
						name = parts[2]
						remainder = parts[3:]
					} else {
						rejoin = append(rejoin, parts[:1]...)
					}

					rejoin = append(rejoin, fmt.Sprintf("%s_%s", name, hash))
					rejoin = append(rejoin, remainder...)

					reference = strings.Join(rejoin, ".")
				}
				return terraform.PlanReference{Value: reference}, false
			case "constant_value":
				return v, false
			}
		}
	}

	return nil, false
}

func getConfiguration(address string, configuration ConfigurationModule) *ConfigurationResource {

	workingAddress := address
	var moduleParts []string
	for strings.HasPrefix(workingAddress, "module.") {
		workingAddressParts := strings.Split(workingAddress, ".")
		moduleParts = append(moduleParts, workingAddressParts[1])
		workingAddress = strings.Join(workingAddressParts[2:], ".")
	}

	workingModule := configuration
	for _, moduleName := range moduleParts {
		if module, ok := workingModule.ModuleCalls[moduleName]; ok {
			workingModule = module.Module
		}
	}

	for _, resource := range workingModule.Resources {
		if resource.Address == workingAddress {
			return &resource
		}
	}

	return nil
}

func getValues(address string, resourceChange []ResourceChange) *ResourceChange {
	for _, r := range resourceChange {
		if r.Address == address {
			return &r
		}
	}
	return nil
}
