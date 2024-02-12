package state

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"

	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/rds"

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
								BackupRetentionPeriodDays: defsecTypes.Int(1, defsecTypes.Metadata{}),
								ReplicationSourceARN:      defsecTypes.String("arn:whatever", defsecTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: defsecTypes.Metadata{},
									Enabled:  defsecTypes.Bool(true, defsecTypes.Metadata{}),
									KMSKeyID: defsecTypes.String("keyidhere", defsecTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       defsecTypes.Metadata{},
									EncryptStorage: defsecTypes.Bool(true, defsecTypes.Metadata{}),
									KMSKeyID:       defsecTypes.String("keyidhere", defsecTypes.Metadata{}),
								},
								PublicAccess: defsecTypes.Bool(true, defsecTypes.Metadata{}),
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
								BackupRetentionPeriodDays: defsecTypes.Int(1, defsecTypes.Metadata{}),
								ReplicationSourceARN:      defsecTypes.String("arn:whatever", defsecTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: defsecTypes.Metadata{},
									Enabled:  defsecTypes.Bool(true, defsecTypes.Metadata{}),
									KMSKeyID: defsecTypes.String("keyidhere", defsecTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       defsecTypes.Metadata{},
									EncryptStorage: defsecTypes.Bool(true, defsecTypes.Metadata{}),
									KMSKeyID:       defsecTypes.String("keyidhere", defsecTypes.Metadata{}),
								},
								PublicAccess: defsecTypes.Bool(true, defsecTypes.Metadata{}),
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
								BackupRetentionPeriodDays: defsecTypes.Int(1, defsecTypes.Metadata{}),
								ReplicationSourceARN:      defsecTypes.String("arn:whatever", defsecTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: defsecTypes.Metadata{},
									Enabled:  defsecTypes.Bool(true, defsecTypes.Metadata{}),
									KMSKeyID: defsecTypes.String("keyidhere", defsecTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       defsecTypes.Metadata{},
									EncryptStorage: defsecTypes.Bool(true, defsecTypes.Metadata{}),
									KMSKeyID:       defsecTypes.String("keyidhere", defsecTypes.Metadata{}),
								},
								PublicAccess: defsecTypes.Bool(true, defsecTypes.Metadata{}),
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
								BackupRetentionPeriodDays: defsecTypes.Int(1, defsecTypes.Metadata{}),
								ReplicationSourceARN:      defsecTypes.String("arn:whatever", defsecTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: defsecTypes.Metadata{},
									Enabled:  defsecTypes.Bool(true, defsecTypes.Metadata{}),
									KMSKeyID: defsecTypes.String("keyidhere", defsecTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       defsecTypes.Metadata{},
									EncryptStorage: defsecTypes.Bool(true, defsecTypes.Metadata{}),
									KMSKeyID:       defsecTypes.String("keyidhere", defsecTypes.Metadata{}),
								},
								PublicAccess: defsecTypes.Bool(true, defsecTypes.Metadata{}),
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
								BackupRetentionPeriodDays: defsecTypes.Int(1, defsecTypes.Metadata{}),
								ReplicationSourceARN:      defsecTypes.String("arn:whatever", defsecTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: defsecTypes.Metadata{},
									Enabled:  defsecTypes.Bool(true, defsecTypes.Metadata{}),
									KMSKeyID: defsecTypes.String("keyidhere", defsecTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       defsecTypes.Metadata{},
									EncryptStorage: defsecTypes.Bool(true, defsecTypes.Metadata{}),
									KMSKeyID:       defsecTypes.String("keyidhere", defsecTypes.Metadata{}),
								},
								PublicAccess: defsecTypes.Bool(true, defsecTypes.Metadata{}),
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
								BackupRetentionPeriodDays: defsecTypes.Int(1, defsecTypes.Metadata{}),
								ReplicationSourceARN:      defsecTypes.String("arn:whatever:B", defsecTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: defsecTypes.Metadata{},
									Enabled:  defsecTypes.Bool(true, defsecTypes.Metadata{}),
									KMSKeyID: defsecTypes.String("keyidhere:B", defsecTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       defsecTypes.Metadata{},
									EncryptStorage: defsecTypes.Bool(true, defsecTypes.Metadata{}),
									KMSKeyID:       defsecTypes.String("keyidhere:B", defsecTypes.Metadata{}),
								},
								PublicAccess: defsecTypes.Bool(true, defsecTypes.Metadata{}),
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
								BackupRetentionPeriodDays: defsecTypes.Int(1, defsecTypes.Metadata{}),
								ReplicationSourceARN:      defsecTypes.String("arn:whatever:B", defsecTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: defsecTypes.Metadata{},
									Enabled:  defsecTypes.Bool(true, defsecTypes.Metadata{}),
									KMSKeyID: defsecTypes.String("keyidhere:B", defsecTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       defsecTypes.Metadata{},
									EncryptStorage: defsecTypes.Bool(true, defsecTypes.Metadata{}),
									KMSKeyID:       defsecTypes.String("keyidhere:B", defsecTypes.Metadata{}),
								},
								PublicAccess: defsecTypes.Bool(true, defsecTypes.Metadata{}),
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
								BackupRetentionPeriodDays: defsecTypes.Int(1, defsecTypes.Metadata{}),
								ReplicationSourceARN:      defsecTypes.String("arn:whatever", defsecTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: defsecTypes.Metadata{},
									Enabled:  defsecTypes.Bool(true, defsecTypes.Metadata{}),
									KMSKeyID: defsecTypes.String("keyidhere", defsecTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       defsecTypes.Metadata{},
									EncryptStorage: defsecTypes.Bool(true, defsecTypes.Metadata{}),
									KMSKeyID:       defsecTypes.String("keyidhere", defsecTypes.Metadata{}),
								},
								PublicAccess: defsecTypes.Bool(true, defsecTypes.Metadata{}),
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
								Metadata: defsecTypes.Metadata{},
								MetadataOptions: ec2.MetadataOptions{
									Metadata:     defsecTypes.Metadata{},
									HttpTokens:   defsecTypes.String("something", defsecTypes.Metadata{}),
									HttpEndpoint: defsecTypes.String("something", defsecTypes.Metadata{}),
								},
								UserData: defsecTypes.String("something", defsecTypes.Metadata{}),
								SecurityGroups: []ec2.SecurityGroup{
									{
										Metadata:    defsecTypes.Metadata{},
										IsDefault:   defsecTypes.Bool(true, defsecTypes.Metadata{}),
										Description: defsecTypes.String("something", defsecTypes.Metadata{}),
										IngressRules: []ec2.SecurityGroupRule{
											{
												Metadata:    defsecTypes.Metadata{},
												Description: defsecTypes.String("something", defsecTypes.Metadata{}),
												CIDRs: []defsecTypes.StringValue{
													defsecTypes.String("something", defsecTypes.Metadata{}),
												},
											},
										},
										EgressRules: nil,
										VPCID:       defsecTypes.String("something", defsecTypes.Metadata{}),
									},
								},
								RootBlockDevice: &ec2.BlockDevice{
									Metadata:  defsecTypes.Metadata{},
									Encrypted: defsecTypes.Bool(true, defsecTypes.Metadata{}),
								},
								EBSBlockDevices: []*ec2.BlockDevice{
									{
										Metadata:  defsecTypes.Metadata{},
										Encrypted: defsecTypes.Bool(true, defsecTypes.Metadata{}),
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
								Metadata: defsecTypes.Metadata{},
								MetadataOptions: ec2.MetadataOptions{
									Metadata:     defsecTypes.Metadata{},
									HttpTokens:   defsecTypes.String("something", defsecTypes.Metadata{}),
									HttpEndpoint: defsecTypes.String("something", defsecTypes.Metadata{}),
								},
								UserData: defsecTypes.String("something", defsecTypes.Metadata{}),
								SecurityGroups: []ec2.SecurityGroup{
									{
										Metadata:    defsecTypes.Metadata{},
										IsDefault:   defsecTypes.Bool(true, defsecTypes.Metadata{}),
										Description: defsecTypes.String("something", defsecTypes.Metadata{}),
										IngressRules: []ec2.SecurityGroupRule{
											{
												Metadata:    defsecTypes.Metadata{},
												Description: defsecTypes.String("something", defsecTypes.Metadata{}),
												CIDRs: []defsecTypes.StringValue{
													defsecTypes.String("something", defsecTypes.Metadata{}),
												},
											},
										},
										EgressRules: nil,
										VPCID:       defsecTypes.String("something", defsecTypes.Metadata{}),
									},
								},
								RootBlockDevice: &ec2.BlockDevice{
									Metadata:  defsecTypes.Metadata{},
									Encrypted: defsecTypes.Bool(true, defsecTypes.Metadata{}),
								},
								EBSBlockDevices: []*ec2.BlockDevice{
									{
										Metadata:  defsecTypes.Metadata{},
										Encrypted: defsecTypes.Bool(true, defsecTypes.Metadata{}),
									},
								},
							},
						},
					},
					RDS: rds.RDS{
						Instances: []rds.Instance{
							{
								BackupRetentionPeriodDays: defsecTypes.Int(1, defsecTypes.Metadata{}),
								ReplicationSourceARN:      defsecTypes.String("arn:whatever", defsecTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: defsecTypes.Metadata{},
									Enabled:  defsecTypes.Bool(true, defsecTypes.Metadata{}),
									KMSKeyID: defsecTypes.String("keyidhere", defsecTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       defsecTypes.Metadata{},
									EncryptStorage: defsecTypes.Bool(true, defsecTypes.Metadata{}),
									KMSKeyID:       defsecTypes.String("keyidhere", defsecTypes.Metadata{}),
								},
								PublicAccess: defsecTypes.Bool(true, defsecTypes.Metadata{}),
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
