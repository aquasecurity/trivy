package state

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/providers/aws/ec2"

	defsecTypes "github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy/pkg/providers/aws"
	"github.com/aquasecurity/trivy/pkg/providers/aws/rds"

	"github.com/stretchr/testify/assert"
)

func Test_Merging(t *testing.T) {
	tests := []struct {
		name           string
		a, b, expected State
	}{
		{
			name: "both empty",
		},
		{
			name: "a empty, b has a service",
			b: State{
				AWS: aws.AWS{
					RDS: rds.RDS{
						Instances: []rds.Instance{
							{
								BackupRetentionPeriodDays: defsecTypes.Int(1, defsecTypes.MisconfigMetadata{}),
								ReplicationSourceARN:      defsecTypes.String("arn:whatever", defsecTypes.MisconfigMetadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: defsecTypes.MisconfigMetadata{},
									Enabled:  defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
									KMSKeyID: defsecTypes.String("keyidhere", defsecTypes.MisconfigMetadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       defsecTypes.MisconfigMetadata{},
									EncryptStorage: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
									KMSKeyID:       defsecTypes.String("keyidhere", defsecTypes.MisconfigMetadata{}),
								},
								PublicAccess: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
							},
						},
					},
				},
			},
			expected: State{
				AWS: aws.AWS{
					RDS: rds.RDS{
						Instances: []rds.Instance{
							{
								BackupRetentionPeriodDays: defsecTypes.Int(1, defsecTypes.MisconfigMetadata{}),
								ReplicationSourceARN:      defsecTypes.String("arn:whatever", defsecTypes.MisconfigMetadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: defsecTypes.MisconfigMetadata{},
									Enabled:  defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
									KMSKeyID: defsecTypes.String("keyidhere", defsecTypes.MisconfigMetadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       defsecTypes.MisconfigMetadata{},
									EncryptStorage: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
									KMSKeyID:       defsecTypes.String("keyidhere", defsecTypes.MisconfigMetadata{}),
								},
								PublicAccess: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
							},
						},
					},
				},
			},
		},
		{
			name: "b empty, a has a service",
			a: State{
				AWS: aws.AWS{
					RDS: rds.RDS{
						Instances: []rds.Instance{
							{
								BackupRetentionPeriodDays: defsecTypes.Int(1, defsecTypes.MisconfigMetadata{}),
								ReplicationSourceARN:      defsecTypes.String("arn:whatever", defsecTypes.MisconfigMetadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: defsecTypes.MisconfigMetadata{},
									Enabled:  defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
									KMSKeyID: defsecTypes.String("keyidhere", defsecTypes.MisconfigMetadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       defsecTypes.MisconfigMetadata{},
									EncryptStorage: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
									KMSKeyID:       defsecTypes.String("keyidhere", defsecTypes.MisconfigMetadata{}),
								},
								PublicAccess: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
							},
						},
					},
				},
			},
			expected: State{
				AWS: aws.AWS{
					RDS: rds.RDS{
						Instances: []rds.Instance{
							{
								BackupRetentionPeriodDays: defsecTypes.Int(1, defsecTypes.MisconfigMetadata{}),
								ReplicationSourceARN:      defsecTypes.String("arn:whatever", defsecTypes.MisconfigMetadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: defsecTypes.MisconfigMetadata{},
									Enabled:  defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
									KMSKeyID: defsecTypes.String("keyidhere", defsecTypes.MisconfigMetadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       defsecTypes.MisconfigMetadata{},
									EncryptStorage: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
									KMSKeyID:       defsecTypes.String("keyidhere", defsecTypes.MisconfigMetadata{}),
								},
								PublicAccess: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
							},
						},
					},
				},
			},
		},
		{
			name: "both have differing versions of same service",
			a: State{
				AWS: aws.AWS{
					RDS: rds.RDS{
						Instances: []rds.Instance{
							{
								BackupRetentionPeriodDays: defsecTypes.Int(1, defsecTypes.MisconfigMetadata{}),
								ReplicationSourceARN:      defsecTypes.String("arn:whatever", defsecTypes.MisconfigMetadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: defsecTypes.MisconfigMetadata{},
									Enabled:  defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
									KMSKeyID: defsecTypes.String("keyidhere", defsecTypes.MisconfigMetadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       defsecTypes.MisconfigMetadata{},
									EncryptStorage: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
									KMSKeyID:       defsecTypes.String("keyidhere", defsecTypes.MisconfigMetadata{}),
								},
								PublicAccess: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
							},
						},
					},
				},
			},
			b: State{
				AWS: aws.AWS{
					RDS: rds.RDS{
						Instances: []rds.Instance{
							{
								BackupRetentionPeriodDays: defsecTypes.Int(1, defsecTypes.MisconfigMetadata{}),
								ReplicationSourceARN:      defsecTypes.String("arn:whatever:B", defsecTypes.MisconfigMetadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: defsecTypes.MisconfigMetadata{},
									Enabled:  defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
									KMSKeyID: defsecTypes.String("keyidhere:B", defsecTypes.MisconfigMetadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       defsecTypes.MisconfigMetadata{},
									EncryptStorage: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
									KMSKeyID:       defsecTypes.String("keyidhere:B", defsecTypes.MisconfigMetadata{}),
								},
								PublicAccess: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
							},
						},
					},
				},
			},
			expected: State{
				AWS: aws.AWS{
					RDS: rds.RDS{
						Instances: []rds.Instance{
							{
								BackupRetentionPeriodDays: defsecTypes.Int(1, defsecTypes.MisconfigMetadata{}),
								ReplicationSourceARN:      defsecTypes.String("arn:whatever:B", defsecTypes.MisconfigMetadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: defsecTypes.MisconfigMetadata{},
									Enabled:  defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
									KMSKeyID: defsecTypes.String("keyidhere:B", defsecTypes.MisconfigMetadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       defsecTypes.MisconfigMetadata{},
									EncryptStorage: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
									KMSKeyID:       defsecTypes.String("keyidhere:B", defsecTypes.MisconfigMetadata{}),
								},
								PublicAccess: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
							},
						},
					},
				},
			},
		},
		{
			name: "each has a different service",
			a: State{
				AWS: aws.AWS{
					RDS: rds.RDS{
						Instances: []rds.Instance{
							{
								BackupRetentionPeriodDays: defsecTypes.Int(1, defsecTypes.MisconfigMetadata{}),
								ReplicationSourceARN:      defsecTypes.String("arn:whatever", defsecTypes.MisconfigMetadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: defsecTypes.MisconfigMetadata{},
									Enabled:  defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
									KMSKeyID: defsecTypes.String("keyidhere", defsecTypes.MisconfigMetadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       defsecTypes.MisconfigMetadata{},
									EncryptStorage: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
									KMSKeyID:       defsecTypes.String("keyidhere", defsecTypes.MisconfigMetadata{}),
								},
								PublicAccess: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
							},
						},
					},
				},
			},
			b: State{
				AWS: aws.AWS{
					EC2: ec2.EC2{
						Instances: []ec2.Instance{
							{
								Metadata: defsecTypes.MisconfigMetadata{},
								MetadataOptions: ec2.MetadataOptions{
									Metadata:     defsecTypes.MisconfigMetadata{},
									HttpTokens:   defsecTypes.String("something", defsecTypes.MisconfigMetadata{}),
									HttpEndpoint: defsecTypes.String("something", defsecTypes.MisconfigMetadata{}),
								},
								UserData: defsecTypes.String("something", defsecTypes.MisconfigMetadata{}),
								SecurityGroups: []ec2.SecurityGroup{
									{
										Metadata:    defsecTypes.MisconfigMetadata{},
										IsDefault:   defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
										Description: defsecTypes.String("something", defsecTypes.MisconfigMetadata{}),
										IngressRules: []ec2.SecurityGroupRule{
											{
												Metadata:    defsecTypes.MisconfigMetadata{},
												Description: defsecTypes.String("something", defsecTypes.MisconfigMetadata{}),
												CIDRs: []defsecTypes.StringValue{
													defsecTypes.String("something", defsecTypes.MisconfigMetadata{}),
												},
											},
										},
										EgressRules: nil,
										VPCID:       defsecTypes.String("something", defsecTypes.MisconfigMetadata{}),
									},
								},
								RootBlockDevice: &ec2.BlockDevice{
									Metadata:  defsecTypes.MisconfigMetadata{},
									Encrypted: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
								},
								EBSBlockDevices: []*ec2.BlockDevice{
									{
										Metadata:  defsecTypes.MisconfigMetadata{},
										Encrypted: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
									},
								},
							},
						},
					},
				},
			},
			expected: State{
				AWS: aws.AWS{
					EC2: ec2.EC2{
						Instances: []ec2.Instance{
							{
								Metadata: defsecTypes.MisconfigMetadata{},
								MetadataOptions: ec2.MetadataOptions{
									Metadata:     defsecTypes.MisconfigMetadata{},
									HttpTokens:   defsecTypes.String("something", defsecTypes.MisconfigMetadata{}),
									HttpEndpoint: defsecTypes.String("something", defsecTypes.MisconfigMetadata{}),
								},
								UserData: defsecTypes.String("something", defsecTypes.MisconfigMetadata{}),
								SecurityGroups: []ec2.SecurityGroup{
									{
										Metadata:    defsecTypes.MisconfigMetadata{},
										IsDefault:   defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
										Description: defsecTypes.String("something", defsecTypes.MisconfigMetadata{}),
										IngressRules: []ec2.SecurityGroupRule{
											{
												Metadata:    defsecTypes.MisconfigMetadata{},
												Description: defsecTypes.String("something", defsecTypes.MisconfigMetadata{}),
												CIDRs: []defsecTypes.StringValue{
													defsecTypes.String("something", defsecTypes.MisconfigMetadata{}),
												},
											},
										},
										EgressRules: nil,
										VPCID:       defsecTypes.String("something", defsecTypes.MisconfigMetadata{}),
									},
								},
								RootBlockDevice: &ec2.BlockDevice{
									Metadata:  defsecTypes.MisconfigMetadata{},
									Encrypted: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
								},
								EBSBlockDevices: []*ec2.BlockDevice{
									{
										Metadata:  defsecTypes.MisconfigMetadata{},
										Encrypted: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
									},
								},
							},
						},
					},
					RDS: rds.RDS{
						Instances: []rds.Instance{
							{
								BackupRetentionPeriodDays: defsecTypes.Int(1, defsecTypes.MisconfigMetadata{}),
								ReplicationSourceARN:      defsecTypes.String("arn:whatever", defsecTypes.MisconfigMetadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: defsecTypes.MisconfigMetadata{},
									Enabled:  defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
									KMSKeyID: defsecTypes.String("keyidhere", defsecTypes.MisconfigMetadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       defsecTypes.MisconfigMetadata{},
									EncryptStorage: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
									KMSKeyID:       defsecTypes.String("keyidhere", defsecTypes.MisconfigMetadata{}),
								},
								PublicAccess: defsecTypes.Bool(true, defsecTypes.MisconfigMetadata{}),
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := test.b
			actual, err := test.a.Merge(&state)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, test.expected, *actual)
		})
	}

}
