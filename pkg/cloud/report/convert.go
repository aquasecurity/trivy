package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	"github.com/aquasecurity/defsec/pkg/scan"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func ConvertResults(results scan.Results, provider string, scoped []string) map[string]ResultsAtTime {
	convertedResults := make(map[string]ResultsAtTime)
	resultsByServiceAndARN := make(map[string]map[string]scan.Results)
	for _, result := range results {

		service := result.Rule().Service
		resource := result.Flatten().Resource
		if service == "" || service == "general" {
			if parsed, err := arn.Parse(resource); err == nil {
				service = parsed.Service
			}
		}

		existingService, ok := resultsByServiceAndARN[service]
		if !ok {
			existingService = make(map[string]scan.Results)
		}

		existingService[resource] = append(existingService[resource], result)
		resultsByServiceAndARN[service] = existingService
	}
	// ensure we have entries for all scoped services, even if there are no results
	for _, service := range scoped {
		if _, ok := resultsByServiceAndARN[service]; !ok {
			resultsByServiceAndARN[service] = nil
		}
	}
	for service, arnResults := range resultsByServiceAndARN {

		var convertedArnResults []types.Result

		for arn, serviceResults := range arnResults {

			arnResult := types.Result{
				Target: arn,
				Class:  types.ClassConfig,
				Type:   ftypes.Cloud,
			}

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

				arnResult.Misconfigurations = append(arnResult.Misconfigurations, types.DetectedMisconfiguration{
					Type:        provider,
					ID:          result.Rule().AVDID,
					AVDID:       result.Rule().AVDID,
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
						Service:   service,
						StartLine: flat.Location.StartLine,
						EndLine:   flat.Location.EndLine,
					},
				})
			}

			convertedArnResults = append(convertedArnResults, arnResult)
		}
		convertedResults[service] = ResultsAtTime{
			Results:      convertedArnResults,
			CreationTime: time.Now(),
		}
	}
	return convertedResults
}
