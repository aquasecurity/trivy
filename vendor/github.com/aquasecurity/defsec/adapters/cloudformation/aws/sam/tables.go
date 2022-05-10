package sam

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/sam"
)

func getSimpleTables(cfFile parser.FileContext) (tables []sam.SimpleTable) {

	tableResources := cfFile.GetResourceByType("AWS::Serverless::SimpleTable")
	for _, r := range tableResources {
		table := sam.SimpleTable{
			Metadata:         r.Metadata(),
			TableName:        r.GetStringProperty("TableName"),
			SSESpecification: getSSESpecification(r),
		}

		tables = append(tables, table)
	}

	return tables
}

func getSSESpecification(r *parser.Resource) sam.SSESpecification {
	sse := r.GetProperty("SSESpecification")
	if sse.IsNil() {
		return sam.SSESpecification{
			Metadata:       r.Metadata(),
			Enabled:        types.BoolDefault(false, r.Metadata()),
			KMSMasterKeyID: types.StringDefault("", r.Metadata()),
		}
	}

	return sam.SSESpecification{
		Metadata:       sse.Metadata(),
		Enabled:        sse.GetBoolProperty("SSEEnabled"),
		KMSMasterKeyID: sse.GetStringProperty("KMSMasterKeyID"),
	}
}
