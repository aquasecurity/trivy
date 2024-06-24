package terraform

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/zclconf/go-cty/cty"
)

func createPresetValues(b *Block) map[string]cty.Value {
	presets := make(map[string]cty.Value)

	// here we set up common "id" values that are set by the provider - this ensures all blocks have a default
	// referencable id/arn. this isn't perfect, but the only way to link blocks in certain circumstances.
	presets["id"] = cty.StringVal(b.ID())

	if strings.HasPrefix(b.TypeLabel(), "aws_") {
		presets["arn"] = cty.StringVal(b.ID())
	}

	// workaround for weird iam feature
	switch b.TypeLabel() {
	case "aws_iam_policy_document":
		presets["json"] = cty.StringVal(b.ID())
	// If the user leaves the name blank, Terraform will automatically generate a unique name
	case "aws_launch_template":
		presets["name"] = cty.StringVal(uuid.New().String())
	}

	return presets

}

func postProcessValues(b *Block, input map[string]cty.Value) map[string]cty.Value {

	// alias id to "bucket" (bucket name) for s3 bucket resources
	if strings.HasPrefix(b.TypeLabel(), "aws_s3_bucket") {
		if bucket, ok := input["bucket"]; ok {
			input["id"] = bucket
		} else {
			input["bucket"] = cty.StringVal(b.ID())
		}
	}

	if b.TypeLabel() == "aws_s3_bucket" {
		var bucketName string
		if bucket := input["bucket"]; bucket.Type().Equals(cty.String) {
			bucketName = bucket.AsString()
		}
		input["arn"] = cty.StringVal(fmt.Sprintf("arn:aws:s3:::%s", bucketName))
	}

	return input
}
