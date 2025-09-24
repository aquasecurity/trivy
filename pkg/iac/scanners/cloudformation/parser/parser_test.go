package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
)

func parseFile(t *testing.T, source, name string) (FileContexts, error) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, name), []byte(source), 0o600))
	fs := os.DirFS(tmp)
	return New().ParseFS(t.Context(), fs, ".")
}

func Test_parse_yaml(t *testing.T) {
	source := `---
Parameters:
  BucketName: 
    Type: String
    Default: naughty
  EncryptBucket:
    Type: Boolean
    Default: false
Resources:
  S3Bucket:
    Type: 'AWS::S3::Bucket'
    Properties:
      BucketName: naughty
      BucketEncryption:
        ServerSideEncryptionConfiguration:
        - BucketKeyEnabled: 
            Ref: EncryptBucket`

	files, err := parseFile(t, source, "cf.yaml")
	require.NoError(t, err)
	assert.Len(t, files, 1)
	file := files[0]

	assert.Len(t, file.Resources, 1)
	assert.Len(t, file.Parameters, 2)

	bucket, ok := file.Resources["S3Bucket"]
	require.True(t, ok, "S3Bucket resource should be available")
	assert.Equal(t, "cf.yaml", bucket.Range().GetFilename())
	assert.Equal(t, 10, bucket.Range().GetStartLine())
	assert.Equal(t, 17, bucket.Range().GetEndLine())
}

func Test_parse_json(t *testing.T) {
	source := `{
  "Parameters": {
    "BucketName": {
      "Type": "String",
      "Default": "naughty"
    },
    "BucketKeyEnabled": {
      "Type": "Boolean",
      "Default": false
    }
  },
  "Resources": {
    "S3Bucket": {
      "Type": "AWS::S3::Bucket",
      "properties": {
        "BucketName": {
          "Ref": "BucketName"
        },
        "BucketEncryption": {
          "ServerSideEncryptionConfiguration": [
            {
              "BucketKeyEnabled": {
                  "Ref": "BucketKeyEnabled"
              }
            }
          ]
        }
      }
    }
  }
}
`

	files, err := parseFile(t, source, "cf.json")
	require.NoError(t, err)
	assert.Len(t, files, 1)
	file := files[0]

	assert.Len(t, file.Resources, 1)
	assert.Len(t, file.Parameters, 2)
}

func Test_parse_yaml_with_map_ref(t *testing.T) {
	source := `---
Parameters:
  BucketName: 
    Type: String
    Default: referencedBucket
  EncryptBucket:
    Type: Boolean
    Default: false
Resources:
  S3Bucket:
    Type: 'AWS::S3::Bucket'
    Properties:
      BucketName:
        Ref: BucketName
      BucketEncryption:
        ServerSideEncryptionConfiguration:
        - BucketKeyEnabled: 
            Ref: EncryptBucket`

	files, err := parseFile(t, source, "cf.yaml")
	require.NoError(t, err)
	assert.Len(t, files, 1)
	file := files[0]

	assert.Len(t, file.Resources, 1)
	assert.Len(t, file.Parameters, 2)

	res := file.GetResourceByLogicalID("S3Bucket")
	assert.NotNil(t, res)

	refProp := res.GetProperty("BucketName")
	assert.False(t, refProp.IsNil())
	assert.Equal(t, "referencedBucket", refProp.AsString())
}

func Test_parse_yaml_with_intrinsic_functions(t *testing.T) {
	source := `---
Parameters:
  BucketName: 
    Type: String
    Default: somebucket
  EncryptBucket:
    Type: Boolean
    Default: false
Resources:
  S3Bucket:
    Type: 'AWS::S3::Bucket'
    Properties:
      BucketName: !Ref BucketName
      BucketEncryption:
        ServerSideEncryptionConfiguration:
        - BucketKeyEnabled: false
`

	files, err := parseFile(t, source, "cf.yaml")
	require.NoError(t, err)
	assert.Len(t, files, 1)
	ctx := files[0]

	assert.Len(t, ctx.Resources, 1)
	assert.Len(t, ctx.Parameters, 2)

	res := ctx.GetResourceByLogicalID("S3Bucket")
	assert.NotNil(t, res)

	refProp := res.GetProperty("BucketName")
	assert.False(t, refProp.IsNil())
	assert.Equal(t, "somebucket", refProp.AsString())
}

func createTestFileContext(t *testing.T, source string) *FileContext {
	contexts, err := parseFile(t, source, "main.yaml")
	require.NoError(t, err)
	require.Len(t, contexts, 1)
	return contexts[0]
}

func Test_parse_yaml_use_condition_in_resource(t *testing.T) {
	source := `---
AWSTemplateFormatVersion: "2010-09-09"
Description: some description
Parameters:
  ServiceName:
    Type: String
    Description: The service name
  EnvName:
    Type: String
    Description: Optional environment name to prefix all resources with
    Default: ""

Conditions:
  SuffixResources: !Not [!Equals [!Ref EnvName, ""]]

Resources:
  ErrorTimedOutMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      FilterPattern: '?ERROR ?error ?Error ?"timed out"' # If log contains one of these error words or timed out
      LogGroupName:
        !If [
          SuffixResources,
          !Sub "/aws/lambda/${ServiceName}-${EnvName}",
          !Sub "/aws/lambda/${ServiceName}",
        ]
      MetricTransformations:
        - MetricName: !Sub "${ServiceName}-ErrorLogCount"
          MetricNamespace: market-LogMetrics
          MetricValue: 1
          DefaultValue: 0
`

	files, err := parseFile(t, source, "cf.yaml")
	require.NoError(t, err)
	assert.Len(t, files, 1)
	ctx := files[0]

	assert.Len(t, ctx.Parameters, 2)
	assert.Len(t, ctx.Conditions, 1)
	assert.Len(t, ctx.Resources, 1)

	res := ctx.GetResourceByLogicalID("ErrorTimedOutMetricFilter")
	assert.NotNil(t, res)

	refProp := res.GetProperty("LogGroupName")
	assert.False(t, refProp.IsNil())
	assert.Equal(t, "/aws/lambda/${ServiceName}", refProp.AsString())
}

func TestParse_WithParameters(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"main.yaml": `AWSTemplateFormatVersion: 2010-09-09
Parameters:
  KmsMasterKeyId:
    Type: String
Resources:
  TestQueue:
    Type: 'AWS::SQS::Queue'
    Properties:
      QueueName: test-queue
      KmsMasterKeyId: !Ref KmsMasterKeyId
      `,
	})

	params := map[string]any{
		"KmsMasterKeyId": "some_id",
	}
	p := New(WithParameters(params))

	files, err := p.ParseFS(t.Context(), fs, ".")
	require.NoError(t, err)
	require.Len(t, files, 1)

	file := files[0]
	res := file.GetResourceByLogicalID("TestQueue")
	assert.NotNil(t, res)

	kmsProp := res.GetProperty("KmsMasterKeyId")
	assert.False(t, kmsProp.IsNil())
	assert.Equal(t, "some_id", kmsProp.AsString())
}

func TestParse_WithParameterFiles(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"main.yaml": `AWSTemplateFormatVersion: 2010-09-09
Parameters:
  KmsMasterKeyId:
    Type: String
Resources:
  TestQueue:
    Type: 'AWS::SQS::Queue'
    Properties:
      QueueName: test-queue
      KmsMasterKeyId: !Ref KmsMasterKeyId
`,
		"params.json": `[
   {
        "ParameterKey": "KmsMasterKeyId",
        "ParameterValue": "some_id"
    }
]
      `,
	})

	p := New(WithParameterFiles("params.json"))

	files, err := p.ParseFS(t.Context(), fs, ".")
	require.NoError(t, err)
	require.Len(t, files, 1)

	file := files[0]
	res := file.GetResourceByLogicalID("TestQueue")
	assert.NotNil(t, res)

	kmsProp := res.GetProperty("KmsMasterKeyId")
	assert.False(t, kmsProp.IsNil())
	assert.Equal(t, "some_id", kmsProp.AsString())
}

func TestParse_WithConfigFS(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"queue.yaml": `AWSTemplateFormatVersion: 2010-09-09
Parameters:
  KmsMasterKeyId:
    Type: String
Resources:
  TestQueue:
    Type: 'AWS::SQS::Queue'
    Properties:
      QueueName: testqueue
      KmsMasterKeyId: !Ref KmsMasterKeyId
`,
		"bucket.yaml": `AWSTemplateFormatVersion: '2010-09-09'
Description: Bucket
Parameters:
  BucketName:
    Type: String
Resources:
  S3Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref BucketName
`,
	})

	configFS := testutil.CreateFS(t, map[string]string{
		"/workdir/parameters/queue.json": `[
      {
           "ParameterKey": "KmsMasterKeyId",
           "ParameterValue": "some_id"
       }
   ]
         `,
		"/workdir/parameters/s3.json": `[
      {
           "ParameterKey": "BucketName",
           "ParameterValue": "testbucket"
       }
   ]`,
	})

	p := New(
		WithParameterFiles("/workdir/parameters/queue.json", "/workdir/parameters/s3.json"),
		WithConfigsFS(configFS),
	)

	files, err := p.ParseFS(t.Context(), fs, ".")
	require.NoError(t, err)
	require.Len(t, files, 2)

	for _, file := range files {
		if strings.Contains(file.filepath, "queue") {
			res := file.GetResourceByLogicalID("TestQueue")
			assert.NotNil(t, res)

			kmsProp := res.GetProperty("KmsMasterKeyId")
			assert.False(t, kmsProp.IsNil())
			assert.Equal(t, "some_id", kmsProp.AsString())
		} else if strings.Contains(file.filepath, "s3") {
			res := file.GetResourceByLogicalID("S3Bucket")
			assert.NotNil(t, res)

			bucketNameProp := res.GetProperty("BucketName")
			assert.False(t, bucketNameProp.IsNil())
			assert.Equal(t, "testbucket", bucketNameProp.AsString())
		}
	}
}

func TestJsonWithNumbers(t *testing.T) {
	src := `
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {
        "SomeIntParam": {
            "Type": "Number",
            "Default": 1
        },
        "SomeFloatParam": {
            "Type": "Number",
            "Default": 1.1
        }
    },
    "Resources": {
        "SomeResource": {
            "Type": "Test::Resource",
            "Properties": {
                "SomeIntProp": 1,
                "SomeFloatProp": 1.1
            }
        }
    }
}
`

	fsys := testutil.CreateFS(t, map[string]string{
		"main.json": src,
	})

	files, err := New().ParseFS(t.Context(), fsys, ".")

	require.NoError(t, err)
	require.Len(t, files, 1)

	file := files[0]

	assert.Equal(t, 1, file.Parameters["SomeIntParam"].Default())
	assert.InEpsilon(t, 1.1, file.Parameters["SomeFloatParam"].Default(), 0.0001)

	res := file.GetResourcesByType("Test::Resource")
	assert.NotNil(t, res)
	assert.Len(t, res, 1)

	assert.Equal(t, 1, res[0].GetProperty("SomeIntProp").AsIntValue().Value())
	assert.Equal(t, 0, res[0].GetProperty("SomeFloatProp").AsIntValue().Value())
}

func TestParameterIsNull(t *testing.T) {
	src := `---
AWSTemplateFormatVersion: 2010-09-09

Parameters:
  Email:
    Type: String

Conditions:
  SubscribeEmail: !Not [!Equals [ !Ref Email, ""]]
`

	fsys := testutil.CreateFS(t, map[string]string{
		"main.yaml": src,
	})

	files, err := New().ParseFS(t.Context(), fsys, ".")
	require.NoError(t, err)
	require.Len(t, files, 1)
}

func Test_TemplateWithNullProperty(t *testing.T) {
	src := `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  TestBucket:
    Type: "AWS::S3::Bucket"
    Properties:
      BucketName:`

	fsys := testutil.CreateFS(t, map[string]string{
		"main.yaml": src,
	})

	files, err := New().ParseFS(t.Context(), fsys, ".")
	require.NoError(t, err)
	require.Len(t, files, 1)

	file := files[0]

	res := file.GetResourceByLogicalID("TestBucket")

	assert.True(t, res.GetProperty("BucketName").IsNil())
}

func Test_TemplateWithNullNestedProperty(t *testing.T) {
	src := `AWSTemplateFormatVersion: "2010-09-09"
Description: "BAD"
Resources:
  TestBucket:
    Type: "AWS::S3::Bucket"
    Properties:
      BucketName: test
      PublicAccessBlockConfiguration:
        BlockPublicAcls: null`

	fsys := testutil.CreateFS(t, map[string]string{
		"main.yaml": src,
	})

	files, err := New().ParseFS(t.Context(), fsys, ".")
	require.NoError(t, err)
	require.Len(t, files, 1)

	file := files[0]

	res := file.GetResourceByLogicalID("TestBucket")

	assert.True(t, res.GetProperty("PublicAccessBlockConfiguration.BlockPublicAcls").IsNil())
}

func Test_ExpandForEachYAML(t *testing.T) {
	source := `AWSTemplateFormatVersion: 2010-09-09
Transform: AWS::LanguageExtensions
Parameters:
  TopicNamesParam:
    Type: CommaDelimitedList
    Default: Success,Failure
Mappings:
  Success:
    Properties:
      DisplayName: success
      FifoTopic: true
  Failure:
    Properties:
      DisplayName: failure
      FifoTopic: false
Resources:
  'Fn::ForEach::Topics':
    - TopicName
    - !Split [",", !Ref TopicNamesParam]
    - 'SnsTopic${TopicName}':
        Type: 'AWS::SNS::Topic'
        Properties:
          TopicName: !Sub '${TopicName}.fifo'
          'Fn::ForEach::Properties':
          - PropertyName
          - [DisplayName, FifoTopic]
          - '${PropertyName}':
             'Fn::FindInMap':
               - Ref: 'TopicName'
               - Properties
               - Ref: 'PropertyName'
      'Fn::ForEach::Subscriptions':
      - SubName
      - ['Alpha', 'Beta']
      - 'SnsSubscription${TopicName}${SubName}':
          Type: 'AWS::SNS::Subscription'
          Properties:
            TopicArn: !Ref 'SnsTopic${TopicName}'
            Protocol: email
            Endpoint: !Sub '${SubName}@example.com'
`

	files, err := parseFile(t, source, "cf.yaml")
	require.NoError(t, err)
	file := files[0]

	assert.Len(t, file.Resources, 6)

	tests := []struct {
		LogicalID string
		Props     map[string]any
	}{
		// SnsTopic
		{
			"SnsTopicSuccess",
			map[string]any{
				"TopicName":   "Success.fifo",
				"DisplayName": "success",
				"FifoTopic":   true,
			},
		},
		{
			"SnsTopicFailure",
			map[string]any{
				"TopicName":   "Failure.fifo",
				"DisplayName": "failure",
				"FifoTopic":   false,
			},
		},
		// SnsSubscription
		{
			"SnsSubscriptionSuccessAlpha",
			map[string]any{
				"TopicArn": "SnsTopicSuccess",
				"Protocol": "email",
				"Endpoint": "Alpha@example.com",
			},
		},
		{
			"SnsSubscriptionSuccessBeta",
			map[string]any{
				"TopicArn": "SnsTopicSuccess",
				"Protocol": "email",
				"Endpoint": "Beta@example.com",
			},
		},
		{
			"SnsSubscriptionFailureAlpha",
			map[string]any{
				"TopicArn": "SnsTopicFailure",
				"Protocol": "email",
				"Endpoint": "Alpha@example.com",
			},
		},
		{
			"SnsSubscriptionFailureBeta",
			map[string]any{
				"TopicArn": "SnsTopicFailure",
				"Protocol": "email",
				"Endpoint": "Beta@example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.LogicalID, func(t *testing.T) {
			res, ok := file.Resources[tt.LogicalID]
			require.True(t, ok)
			for propName, expected := range tt.Props {
				prop := res.GetProperty(propName)
				assert.Equal(t, expected, prop.RawValue())
			}
		})
	}
}

func Test_ExpandForEachJSON(t *testing.T) {
	source := `{
		"AWSTemplateFormatVersion": "2010-09-09",
		"Transform": "AWS::LanguageExtensions",
		"Resources": {
			"Fn::ForEach::Buckets": [
				"Suffix",
				["A", "B"],
				{
					"S3Bucket${Suffix}": {
						"Type": "AWS::S3::Bucket",
						"Properties": {
							"BucketName": { "Fn::Sub": "bucket-${Suffix}" }
						}
					}
				}
			]
		}
	}`

	files, err := parseFile(t, source, "cf.json")
	require.NoError(t, err)
	require.Len(t, files, 1)

	file := files[0]
	require.Len(t, file.Resources, 2)

	b1, ok := file.Resources["S3BucketA"]
	require.True(t, ok)
	assert.Equal(t, "AWS::S3::Bucket", b1.Type())
	assert.Equal(t, "bucket-A", b1.GetProperty("BucketName").AsString())

	b2, ok := file.Resources["S3BucketB"]
	require.True(t, ok)
	assert.Equal(t, "AWS::S3::Bucket", b2.Type())
	assert.Equal(t, "bucket-B", b2.GetProperty("BucketName").AsString())
}
