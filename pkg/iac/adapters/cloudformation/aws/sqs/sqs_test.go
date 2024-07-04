package sqs

import (
	"testing"

	"github.com/liamg/iamgo"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/sqs"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected sqs.SQS
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: '2010-09-09'
Resources: 
  MyQueue: 
    Type: AWS::SQS::Queue
    Properties: 
      QueueName: "SampleQueue"
      KmsMasterKeyId: mykey
  SampleSQSPolicy: 
    Type: AWS::SQS::QueuePolicy
    Properties: 
      Queues: 
        - !Ref MyQueue
      PolicyDocument: 
        Statement: 
          - 
            Action: 
              - "SQS:SendMessage"
            Effect: "Allow"
            Resource: "arn:aws:sqs:us-east-2:444455556666:queue2"
`,
			expected: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Encryption: sqs.Encryption{
							KMSKeyID: types.StringTest("mykey"),
						},
						Policies: []iam.Policy{
							{
								Document: func() iam.Document {
									return iam.Document{
										Parsed: iamgo.NewPolicyBuilder().
											WithStatement(
												iamgo.NewStatementBuilder().
													WithEffect("Allow").
													WithActions([]string{"SQS:SendMessage"}).
													WithResources([]string{"arn:aws:sqs:us-east-2:444455556666:queue2"}).
													Build(),
											).
											Build(),
									}
								}(),
							},
						},
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  MySNSTopic:
    Type: AWS::SQS::Queue
  `,
			expected: sqs.SQS{
				Queues: []sqs.Queue{{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
