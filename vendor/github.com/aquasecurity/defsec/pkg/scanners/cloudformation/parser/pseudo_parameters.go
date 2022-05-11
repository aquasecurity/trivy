package parser

var pseudoParameters = map[string]interface{}{
	"AWS::AccountId":        "123456789012",
	"AWS::NotificationARNs": []string{"notification::arn::1", "notification::arn::2"},
	"AWS::NoValue":          "",
	"AWS::Partition":        "aws",
	"AWS::Region":           "eu-west-1",
	"AWS::StackId":          "arn:aws:cloudformation:eu-west-1:stack/ID",
	"AWS::StackName":        "cfsec-test-stack",
}
