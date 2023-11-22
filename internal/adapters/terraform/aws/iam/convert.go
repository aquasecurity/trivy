package iam

import (
	"strings"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/terraform"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"

	"github.com/liamg/iamgo"
)

type wrappedDocument struct {
	Source   scan.MetadataProvider
	Document iamgo.Document
}

func ParsePolicyFromAttr(attr *terraform.Attribute, owner *terraform.Block, modules terraform.Modules) (*iam.Document, error) {

	documents := findAllPolicies(modules, owner, attr)
	if len(documents) > 0 {
		return &iam.Document{
			Parsed:   documents[0].Document,
			Metadata: documents[0].Source.GetMetadata(),
			IsOffset: true,
		}, nil
	}

	if attr.IsString() {

		dataBlock, err := modules.GetBlockById(attr.Value().AsString())
		if err != nil {
			parsed, err := iamgo.Parse([]byte(unescapeVars(attr.Value().AsString())))
			if err != nil {
				return nil, err
			}
			return &iam.Document{
				Parsed:   *parsed,
				Metadata: attr.GetMetadata(),
				IsOffset: false,
				HasRefs:  len(attr.AllReferences()) > 0,
			}, nil
		} else if dataBlock.Type() == "data" && dataBlock.TypeLabel() == "aws_iam_policy_document" {
			if doc, err := ConvertTerraformDocument(modules, dataBlock); err == nil {
				return &iam.Document{
					Metadata: dataBlock.GetMetadata(),
					Parsed:   doc.Document,
					IsOffset: true,
					HasRefs:  false,
				}, nil
			}
		}
	}

	return &iam.Document{
		Metadata: owner.GetMetadata(),
	}, nil
}

func unescapeVars(input string) string {
	return strings.ReplaceAll(input, "&{", "${")
}

// ConvertTerraformDocument converts a terraform data policy into an iamgo policy https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document
func ConvertTerraformDocument(modules terraform.Modules, block *terraform.Block) (*wrappedDocument, error) {

	builder := iamgo.NewPolicyBuilder()

	if sourceAttr := block.GetAttribute("source_json"); sourceAttr.IsString() {
		doc, err := iamgo.ParseString(sourceAttr.Value().AsString())
		if err != nil {
			return nil, err
		}
		builder = iamgo.PolicyBuilderFromDocument(*doc)
	}

	if sourceDocumentsAttr := block.GetAttribute("source_policy_documents"); sourceDocumentsAttr.IsIterable() {
		docs := findAllPolicies(modules, block, sourceDocumentsAttr)
		for _, doc := range docs {
			statements, _ := doc.Document.Statements()
			for _, statement := range statements {
				builder.WithStatement(statement)
			}
		}
	}

	if idAttr := block.GetAttribute("policy_id"); idAttr.IsString() {
		r := idAttr.GetMetadata().Range()
		builder.WithId(idAttr.Value().AsString(), r.GetStartLine(), r.GetEndLine())
	}

	if versionAttr := block.GetAttribute("version"); versionAttr.IsString() {
		r := versionAttr.GetMetadata().Range()
		builder.WithVersion(versionAttr.Value().AsString(), r.GetStartLine(), r.GetEndLine())
	}

	for _, statementBlock := range block.GetBlocks("statement") {
		statement := parseStatement(statementBlock)
		builder.WithStatement(statement, statement.Range().StartLine, statement.Range().EndLine)
	}

	if overrideDocumentsAttr := block.GetAttribute("override_policy_documents"); overrideDocumentsAttr.IsIterable() {
		docs := findAllPolicies(modules, block, overrideDocumentsAttr)
		for _, doc := range docs {
			statements, _ := doc.Document.Statements()
			for _, statement := range statements {
				builder.WithStatement(statement, statement.Range().StartLine, statement.Range().EndLine)
			}
		}
	}

	return &wrappedDocument{Document: builder.Build(), Source: block}, nil
}

// nolint
func parseStatement(statementBlock *terraform.Block) iamgo.Statement {

	metadata := statementBlock.GetMetadata()

	builder := iamgo.NewStatementBuilder()
	builder.WithRange(metadata.Range().GetStartLine(), metadata.Range().GetEndLine())

	if sidAttr := statementBlock.GetAttribute("sid"); sidAttr.IsString() {
		r := sidAttr.GetMetadata().Range()
		builder.WithSid(sidAttr.Value().AsString(), r.GetStartLine(), r.GetEndLine())
	}
	if actionsAttr := statementBlock.GetAttribute("actions"); actionsAttr.IsIterable() {
		r := actionsAttr.GetMetadata().Range()
		values := actionsAttr.AsStringValues().AsStrings()
		builder.WithActions(values, r.GetStartLine(), r.GetEndLine())
	}
	if notActionsAttr := statementBlock.GetAttribute("not_actions"); notActionsAttr.IsIterable() {
		r := notActionsAttr.GetMetadata().Range()
		values := notActionsAttr.AsStringValues().AsStrings()
		builder.WithNotActions(values, r.GetStartLine(), r.GetEndLine())
	}
	if resourcesAttr := statementBlock.GetAttribute("resources"); resourcesAttr.IsIterable() {
		r := resourcesAttr.GetMetadata().Range()
		values := resourcesAttr.AsStringValues().AsStrings()
		builder.WithResources(values, r.GetStartLine(), r.GetEndLine())
	}
	if notResourcesAttr := statementBlock.GetAttribute("not_resources"); notResourcesAttr.IsIterable() {
		r := notResourcesAttr.GetMetadata().Range()
		values := notResourcesAttr.AsStringValues().AsStrings()
		builder.WithNotResources(values, r.GetStartLine(), r.GetEndLine())
	}
	if effectAttr := statementBlock.GetAttribute("effect"); effectAttr.IsString() {
		r := effectAttr.GetMetadata().Range()
		builder.WithEffect(effectAttr.Value().AsString(), r.GetStartLine(), r.GetEndLine())
	} else {
		builder.WithEffect(iamgo.EffectAllow)
	}

	for _, principalBlock := range statementBlock.GetBlocks("principals") {
		typeAttr := principalBlock.GetAttribute("type")
		if !typeAttr.IsString() {
			continue
		}
		identifiersAttr := principalBlock.GetAttribute("identifiers")
		if !identifiersAttr.IsIterable() {
			continue
		}
		r := principalBlock.GetMetadata().Range()
		switch typeAttr.Value().AsString() {
		case "*":
			builder.WithAllPrincipals(true, r.GetStartLine(), r.GetEndLine())
		case "AWS":
			values := identifiersAttr.AsStringValues().AsStrings()
			builder.WithAWSPrincipals(values, r.GetStartLine(), r.GetEndLine())
		case "Federated":
			values := identifiersAttr.AsStringValues().AsStrings()
			builder.WithFederatedPrincipals(values, r.GetStartLine(), r.GetEndLine())
		case "Service":
			values := identifiersAttr.AsStringValues().AsStrings()
			builder.WithServicePrincipals(values, r.GetStartLine(), r.GetEndLine())
		case "CanonicalUser":
			values := identifiersAttr.AsStringValues().AsStrings()
			builder.WithCanonicalUsersPrincipals(values, r.GetStartLine(), r.GetEndLine())
		}
	}

	for _, conditionBlock := range statementBlock.GetBlocks("condition") {
		testAttr := conditionBlock.GetAttribute("test")
		if !testAttr.IsString() {
			continue
		}
		variableAttr := conditionBlock.GetAttribute("variable")
		if !variableAttr.IsString() {
			continue
		}
		valuesAttr := conditionBlock.GetAttribute("values")
		values := valuesAttr.AsStringValues().AsStrings()
		if valuesAttr.IsNil() || len(values) == 0 {
			continue
		}

		r := conditionBlock.GetMetadata().Range()

		builder.WithCondition(
			testAttr.Value().AsString(),
			variableAttr.Value().AsString(),
			values,
			r.GetStartLine(),
			r.GetEndLine(),
		)

	}
	return builder.Build()
}

func findAllPolicies(modules terraform.Modules, parentBlock *terraform.Block, attr *terraform.Attribute) []wrappedDocument {
	var documents []wrappedDocument
	for _, ref := range attr.AllReferences() {
		for _, b := range modules.GetBlocks() {
			if b.Type() != "data" || b.TypeLabel() != "aws_iam_policy_document" {
				continue
			}
			if ref.RefersTo(b.Reference()) {
				document, err := ConvertTerraformDocument(modules, b)
				if err != nil {
					continue
				}
				documents = append(documents, *document)
				continue
			}
			kref := *ref
			kref.SetKey(parentBlock.Reference().RawKey())
			if kref.RefersTo(b.Reference()) {
				document, err := ConvertTerraformDocument(modules, b)
				if err != nil {
					continue
				}
				documents = append(documents, *document)
			}
		}
	}
	return documents
}
