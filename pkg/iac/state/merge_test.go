package state

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

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
								BackupRetentionPeriodDays: iacTypes.Int(1, iacTypes.Metadata{}),
								ReplicationSourceARN:      iacTypes.String("arn:whatever", iacTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: iacTypes.Metadata{},
									Enabled:  iacTypes.Bool(true, iacTypes.Metadata{}),
									KMSKeyID: iacTypes.String("keyidhere", iacTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       iacTypes.Metadata{},
									EncryptStorage: iacTypes.Bool(true, iacTypes.Metadata{}),
									KMSKeyID:       iacTypes.String("keyidhere", iacTypes.Metadata{}),
								},
								PublicAccess: iacTypes.Bool(true, iacTypes.Metadata{}),
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
								BackupRetentionPeriodDays: iacTypes.Int(1, iacTypes.Metadata{}),
								ReplicationSourceARN:      iacTypes.String("arn:whatever", iacTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: iacTypes.Metadata{},
									Enabled:  iacTypes.Bool(true, iacTypes.Metadata{}),
									KMSKeyID: iacTypes.String("keyidhere", iacTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       iacTypes.Metadata{},
									EncryptStorage: iacTypes.Bool(true, iacTypes.Metadata{}),
									KMSKeyID:       iacTypes.String("keyidhere", iacTypes.Metadata{}),
								},
								PublicAccess: iacTypes.Bool(true, iacTypes.Metadata{}),
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
								BackupRetentionPeriodDays: iacTypes.Int(1, iacTypes.Metadata{}),
								ReplicationSourceARN:      iacTypes.String("arn:whatever", iacTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: iacTypes.Metadata{},
									Enabled:  iacTypes.Bool(true, iacTypes.Metadata{}),
									KMSKeyID: iacTypes.String("keyidhere", iacTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       iacTypes.Metadata{},
									EncryptStorage: iacTypes.Bool(true, iacTypes.Metadata{}),
									KMSKeyID:       iacTypes.String("keyidhere", iacTypes.Metadata{}),
								},
								PublicAccess: iacTypes.Bool(true, iacTypes.Metadata{}),
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
								BackupRetentionPeriodDays: iacTypes.Int(1, iacTypes.Metadata{}),
								ReplicationSourceARN:      iacTypes.String("arn:whatever", iacTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: iacTypes.Metadata{},
									Enabled:  iacTypes.Bool(true, iacTypes.Metadata{}),
									KMSKeyID: iacTypes.String("keyidhere", iacTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       iacTypes.Metadata{},
									EncryptStorage: iacTypes.Bool(true, iacTypes.Metadata{}),
									KMSKeyID:       iacTypes.String("keyidhere", iacTypes.Metadata{}),
								},
								PublicAccess: iacTypes.Bool(true, iacTypes.Metadata{}),
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
								BackupRetentionPeriodDays: iacTypes.Int(1, iacTypes.Metadata{}),
								ReplicationSourceARN:      iacTypes.String("arn:whatever", iacTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: iacTypes.Metadata{},
									Enabled:  iacTypes.Bool(true, iacTypes.Metadata{}),
									KMSKeyID: iacTypes.String("keyidhere", iacTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       iacTypes.Metadata{},
									EncryptStorage: iacTypes.Bool(true, iacTypes.Metadata{}),
									KMSKeyID:       iacTypes.String("keyidhere", iacTypes.Metadata{}),
								},
								PublicAccess: iacTypes.Bool(true, iacTypes.Metadata{}),
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
								BackupRetentionPeriodDays: iacTypes.Int(1, iacTypes.Metadata{}),
								ReplicationSourceARN:      iacTypes.String("arn:whatever:B", iacTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: iacTypes.Metadata{},
									Enabled:  iacTypes.Bool(true, iacTypes.Metadata{}),
									KMSKeyID: iacTypes.String("keyidhere:B", iacTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       iacTypes.Metadata{},
									EncryptStorage: iacTypes.Bool(true, iacTypes.Metadata{}),
									KMSKeyID:       iacTypes.String("keyidhere:B", iacTypes.Metadata{}),
								},
								PublicAccess: iacTypes.Bool(true, iacTypes.Metadata{}),
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
								BackupRetentionPeriodDays: iacTypes.Int(1, iacTypes.Metadata{}),
								ReplicationSourceARN:      iacTypes.String("arn:whatever:B", iacTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: iacTypes.Metadata{},
									Enabled:  iacTypes.Bool(true, iacTypes.Metadata{}),
									KMSKeyID: iacTypes.String("keyidhere:B", iacTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       iacTypes.Metadata{},
									EncryptStorage: iacTypes.Bool(true, iacTypes.Metadata{}),
									KMSKeyID:       iacTypes.String("keyidhere:B", iacTypes.Metadata{}),
								},
								PublicAccess: iacTypes.Bool(true, iacTypes.Metadata{}),
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
								BackupRetentionPeriodDays: iacTypes.Int(1, iacTypes.Metadata{}),
								ReplicationSourceARN:      iacTypes.String("arn:whatever", iacTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: iacTypes.Metadata{},
									Enabled:  iacTypes.Bool(true, iacTypes.Metadata{}),
									KMSKeyID: iacTypes.String("keyidhere", iacTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       iacTypes.Metadata{},
									EncryptStorage: iacTypes.Bool(true, iacTypes.Metadata{}),
									KMSKeyID:       iacTypes.String("keyidhere", iacTypes.Metadata{}),
								},
								PublicAccess: iacTypes.Bool(true, iacTypes.Metadata{}),
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
								Metadata: iacTypes.Metadata{},
								MetadataOptions: ec2.MetadataOptions{
									Metadata:     iacTypes.Metadata{},
									HttpTokens:   iacTypes.String("something", iacTypes.Metadata{}),
									HttpEndpoint: iacTypes.String("something", iacTypes.Metadata{}),
								},
								UserData: iacTypes.String("something", iacTypes.Metadata{}),
								SecurityGroups: []ec2.SecurityGroup{
									{
										Metadata:    iacTypes.Metadata{},
										IsDefault:   iacTypes.Bool(true, iacTypes.Metadata{}),
										Description: iacTypes.String("something", iacTypes.Metadata{}),
										IngressRules: []ec2.SecurityGroupRule{
											{
												Metadata:    iacTypes.Metadata{},
												Description: iacTypes.String("something", iacTypes.Metadata{}),
												CIDRs: []iacTypes.StringValue{
													iacTypes.String("something", iacTypes.Metadata{}),
												},
											},
										},
										EgressRules: nil,
										VPCID:       iacTypes.String("something", iacTypes.Metadata{}),
									},
								},
								RootBlockDevice: &ec2.BlockDevice{
									Metadata:  iacTypes.Metadata{},
									Encrypted: iacTypes.Bool(true, iacTypes.Metadata{}),
								},
								EBSBlockDevices: []*ec2.BlockDevice{
									{
										Metadata:  iacTypes.Metadata{},
										Encrypted: iacTypes.Bool(true, iacTypes.Metadata{}),
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
								Metadata: iacTypes.Metadata{},
								MetadataOptions: ec2.MetadataOptions{
									Metadata:     iacTypes.Metadata{},
									HttpTokens:   iacTypes.String("something", iacTypes.Metadata{}),
									HttpEndpoint: iacTypes.String("something", iacTypes.Metadata{}),
								},
								UserData: iacTypes.String("something", iacTypes.Metadata{}),
								SecurityGroups: []ec2.SecurityGroup{
									{
										Metadata:    iacTypes.Metadata{},
										IsDefault:   iacTypes.Bool(true, iacTypes.Metadata{}),
										Description: iacTypes.String("something", iacTypes.Metadata{}),
										IngressRules: []ec2.SecurityGroupRule{
											{
												Metadata:    iacTypes.Metadata{},
												Description: iacTypes.String("something", iacTypes.Metadata{}),
												CIDRs: []iacTypes.StringValue{
													iacTypes.String("something", iacTypes.Metadata{}),
												},
											},
										},
										EgressRules: nil,
										VPCID:       iacTypes.String("something", iacTypes.Metadata{}),
									},
								},
								RootBlockDevice: &ec2.BlockDevice{
									Metadata:  iacTypes.Metadata{},
									Encrypted: iacTypes.Bool(true, iacTypes.Metadata{}),
								},
								EBSBlockDevices: []*ec2.BlockDevice{
									{
										Metadata:  iacTypes.Metadata{},
										Encrypted: iacTypes.Bool(true, iacTypes.Metadata{}),
									},
								},
							},
						},
					},
					RDS: rds.RDS{
						Instances: []rds.Instance{
							{
								BackupRetentionPeriodDays: iacTypes.Int(1, iacTypes.Metadata{}),
								ReplicationSourceARN:      iacTypes.String("arn:whatever", iacTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: iacTypes.Metadata{},
									Enabled:  iacTypes.Bool(true, iacTypes.Metadata{}),
									KMSKeyID: iacTypes.String("keyidhere", iacTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       iacTypes.Metadata{},
									EncryptStorage: iacTypes.Bool(true, iacTypes.Metadata{}),
									KMSKeyID:       iacTypes.String("keyidhere", iacTypes.Metadata{}),
								},
								PublicAccess: iacTypes.Bool(true, iacTypes.Metadata{}),
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
