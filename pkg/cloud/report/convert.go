package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/aquasecurity/defsec/pkg/scan"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func convertResults(results scan.Results, provider string) map[string]ResultAtTime {
	convertedResults := make(map[string]ResultAtTime)
	resultsByService := make(map[string]scan.Results)
	for _, result := range results {
		resultsByService[result.Rule().Service] = append(resultsByService[result.Rule().Service], result)
	}
	for service, serviceResults := range resultsByService {
		var converted []types.DetectedMisconfiguration
		for _, result := range serviceResults {

			var primaryURL string

			// empty namespace implies a go rule from defsec, "builtin" refers to a built-in rego rule
			// this ensures we don't generate bad links for custom policies
			if result.RegoNamespace() == "" || strings.HasPrefix(result.RegoNamespace(), "builtin.") {
				primaryURL = fmt.Sprintf("https://avd.aquasec.com/misconfig/%s", strings.ToLower(result.Rule().AVDID))
			}

			status := types.StatusFailure
			switch result.Status() {
			case scan.StatusPassed:
				status = types.StatusPassed
			case scan.StatusIgnored:
				status = types.StatusException
			}

			flat := result.Flatten()

			converted = append(converted, types.DetectedMisconfiguration{
				Type:        provider,
				ID:          result.Rule().AVDID,
				Title:       result.Rule().Summary,
				Description: strings.TrimSpace(result.Rule().Explanation),
				Message:     strings.TrimSpace(result.Description()),
				Namespace:   result.RegoNamespace(),
				Query:       result.RegoRule(),
				Resolution:  result.Rule().Resolution,
				Severity:    string(result.Severity()),
				PrimaryURL:  primaryURL,
				References:  []string{primaryURL},
				Status:      status,
				CauseMetadata: ftypes.CauseMetadata{
					Resource:  flat.Resource,
					Provider:  string(flat.RuleProvider),
					Service:   flat.RuleService,
					StartLine: flat.Location.StartLine,
					EndLine:   flat.Location.EndLine,
				},
			})
		}
		convertedResults[service] = ResultAtTime{
			Result: types.Result{
				Target:            service,
				Class:             types.ClassConfig,
				Type:              ftypes.Cloud,
				Misconfigurations: converted,
			},
			CreationTime: time.Now(),
		}
	}
	return convertedResults
}
